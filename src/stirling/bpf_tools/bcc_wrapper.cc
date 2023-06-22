/*
 * Copyright 2018- The Pixie Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "src/stirling/bpf_tools/bcc_wrapper.h"

#include <linux/perf_event.h>
#include <sys/mount.h>

#include <iostream>
#include <string>

#include <absl/functional/bind_front.h>
#include <magic_enum.hpp>

#include "src/common/base/base.h"
#include "src/common/fs/fs_wrapper.h"
#include "src/common/perf/scoped_timer.h"
#include "src/common/system/config.h"
#include "src/stirling/bpf_tools/task_struct_resolver.h"
#include "src/stirling/utils/linux_headers.h"

namespace px {
namespace stirling {
namespace bpf_tools {

// TODO(yzhao): Read CPU count during runtime and set maxactive to Multiplier * N_CPU. That way, we
// can be relatively more secure against increase of CPU count. Note the default multiplier is 2,
// which is not sufficient, as indicated in Hipster shop.
//
// AWS offers VMs with 96 vCPUs. We bump the number from 2X to 4X, and round up to 2's exponential,
// which gives 4 * 96 == 384 => 512.
//
// The implication of this parameter is explained in the "How Does a Return Probe Work?" section of
// https://www.kernel.org/doc/Documentation/kprobes.txt. In short, this controls the memory space
// used for bookkeeping, which translate to equal number of struct kretprobe in memory.
constexpr int kKprobeMaxActive = 512;

// BCC requires debugfs to be mounted to deploy BPF programs.
// Most kernels already have this mounted, but some do not.
// See https://github.com/iovisor/bcc/blob/master/INSTALL.md.
Status MountDebugFS() {
  std::filesystem::path sys_kernel_debug("/sys/kernel/debug");

  // If the directory is empty, debugfs needs to be mounted.
  PX_ASSIGN_OR_RETURN(bool is_empty, fs::IsEmpty(sys_kernel_debug));
  if (is_empty) {
    LOG(INFO) << absl::Substitute("Debugfs not mounted at $0. Attempting to mount now.",
                                  sys_kernel_debug.string());
    int status = mount("debugfs", sys_kernel_debug.c_str(), "debugfs", /* mountflags */ 0,
                       /* data */ nullptr);
    if (status == -1) {
      return error::Internal("Mount of debugfs failed (required for BCC): $0", strerror(errno));
    }
  }

  return Status::OK();
}

StatusOr<utils::TaskStructOffsets> ResolveTaskStructOffsetsWithRetry() {
  constexpr int kNumAttempts = 3;

  StatusOr<utils::TaskStructOffsets> offsets_status;
  for (int attempt = 0; attempt < kNumAttempts; ++attempt) {
    offsets_status = utils::ResolveTaskStructOffsets();
    if (offsets_status.ok()) {
      break;
    }
  }
  return offsets_status;
}

StatusOr<utils::TaskStructOffsets> BCCWrapper::ComputeTaskStructOffsets() {
  if (task_struct_offsets_opt_.has_value()) {
    LOG(INFO) << "Returning the previously resolved TaskStructOffsets object";
    return task_struct_offsets_opt_.value();
  }

  LOG(INFO) << "Resolving task_struct offsets.";
  PX_ASSIGN_OR_RETURN(task_struct_offsets_opt_, ResolveTaskStructOffsetsWithRetry());

  LOG(INFO) << absl::Substitute("Successfully resolved task_struct offsets: $0",
                                task_struct_offsets_opt_.value().ToString());
  return task_struct_offsets_opt_.value();
}

Status BCCWrapper::InitBPFProgram(std::string_view bpf_program, std::vector<std::string> cflags,
                                  bool requires_linux_headers,
                                  bool always_infer_task_struct_offsets) {
  if (replaying_) {
    LOG(WARNING) << "BCCWrapper::InitBPFProgram(): replay mode.";
    return Status::OK();
  }
  using utils::TaskStructOffsets;

  if (!IsRoot()) {
    return error::PermissionDenied("BCC currently only supported as the root user.");
  }

  if (requires_linux_headers) {
    auto kernel_version = utils::GetCachedKernelVersion();

    // This function will setup linux headers for BPF code deployment.
    // If another BCCWrapper has already run this function, it will just return the same location
    // as the previous one.
    // Note: Could also put this in Stirling Init() function, but then some tests which use
    //       BCCWrapper (e.g. connector_bpf_tests), would have to make sure to call this function.
    //       Thus, it is deemed to be better here.
    PX_ASSIGN_OR_RETURN(const std::filesystem::path sys_headers_dir,
                        utils::FindOrInstallLinuxHeaders());

    LOG(INFO) << absl::Substitute("Using linux headers found at $0 for BCC runtime.",
                                  sys_headers_dir.string());

    // When Linux headers are requested, the BPF code requires various defines to compile:
    //  - START_BOOTTIME_VARNAME: The name of the task_struct variable containing the boottime.
    //                            Prior to Linux 5.5, it was called real_start_time.
    //                            Linux 5.5+ calls it start_boottime.
    //  - GROUP_LEADER_OFFSET_OVERRIDE: When non-zero, this tells BPF how to access
    //                                  task_struct->group_leader via offsets.
    //  - START_BOOTTIME_OFFSET_OVERRIDE: When non-zero, this tells BPF how to access
    //                                    task_struct->start_boottime via offsets.

    constexpr uint32_t kLinux5p5VersionCode = 328960;
    std::string_view boottime_varname =
        kernel_version.code() >= kLinux5p5VersionCode ? "start_boottime" : "real_start_time";

    // Defaults to zero offsets, which tells BPF not to use the offset overrides, and instead to use
    // the offset implied in the included Linux headers.
    utils::TaskStructOffsets offsets = {};
    // When using packaged Linux headers, there is a good chance that the `struct task_struct`
    // is not a perfect match with the version on the host OS (despite our best efforts to account
    // for the kernel config). In such cases, try to resolve the location of the fields we care
    // about, and send them in as an override to the BPF code.
    // Note that if we found local host headers, then we do not typically do this step, because
    // we trust the locally installed headers to be a perfect match.
    // There is a flag to force the task struct fields resolution, in case we don't trust the
    // local headers, and for testing purposes.
    if (utils::g_packaged_headers_installed || always_infer_task_struct_offsets) {
      auto offsets_or = ComputeTaskStructOffsets();
      if (offsets_or.ok()) {
        offsets = offsets_or.ConsumeValueOrDie();
      } else {
        LOG(WARNING) << absl::Substitute(
            "Failed to obtain task_struct offsets, will not override the task_struct offsets, "
            "error: $0",
            offsets_or.ToString());
      }
    }

    cflags.push_back(absl::Substitute("-DSTART_BOOTTIME_VARNAME=$0", boottime_varname));
    cflags.push_back(
        absl::Substitute("-DGROUP_LEADER_OFFSET_OVERRIDE=$0", offsets.group_leader_offset));
    cflags.push_back(
        absl::Substitute("-DSTART_BOOTTIME_OFFSET_OVERRIDE=$0", offsets.real_start_time_offset));
  }

  PX_RETURN_IF_ERROR(MountDebugFS());

  {
    LOG(INFO) << "Initializing BPF program ...";
    ScopedTimer timer("init_bpf_program");
    auto init_res = bpf_.init(std::string(bpf_program), cflags);
    if (!init_res.ok()) {
      return error::Internal("Unable to initialize BCC BPF program: $0", init_res.msg());
    }
  }
  return Status::OK();
}

Status BCCWrapper::AttachKProbe(const KProbeSpec& probe) {
  VLOG(1) << "Deploying kprobe: " << probe.ToString();
  DCHECK(probe.attach_type != BPFProbeAttachType::kReturnInsts);

  if (!replaying_) {
    auto status =
        bpf_.attach_kprobe(GetKProbeTargetName(probe), std::string(probe.probe_fn), 0 /* offset */,
                           static_cast<bpf_probe_attach_type>(probe.attach_type), kKprobeMaxActive);

    // Don't return error if the probe is optional.
    if (!probe.is_optional) {
      PX_RETURN_IF_ERROR(status);
    }

    if (status.ok()) {
      kprobes_.push_back(probe);
      ++num_attached_kprobes_;
    }
  } else {
    ++num_attached_kprobes_;
  }
  return Status::OK();
}

Status BCCWrapper::AttachTracepoint(const TracepointSpec& probe) {
  VLOG(1) << "Deploying tracepoint: " << probe.ToString();

  if (!replaying_) {
    PX_RETURN_IF_ERROR(bpf_.attach_tracepoint(probe.tracepoint, probe.probe_fn));
  }
  tracepoints_.push_back(probe);
  ++num_attached_tracepoints_;
  return Status::OK();
}

Status BCCWrapper::AttachUProbe(const UProbeSpec& probe) {
  if (replaying_) {
    return Status::OK();
  }
  VLOG(1) << "Deploying uprobe: " << probe.ToString();
  // TODO(oazizi): Natively support this attach type in BCCWrapper.
  DCHECK(probe.attach_type != BPFProbeAttachType::kReturnInsts);
  DCHECK((probe.symbol.empty() && probe.address != 0) ||
         (!probe.symbol.empty() && probe.address == 0))
      << "Exactly one of 'symbol' and 'address' must be specified.";
  auto status = bpf_.attach_uprobe(
      probe.binary_path, probe.symbol, std::string(probe.probe_fn), probe.address,
      static_cast<bpf_probe_attach_type>(probe.attach_type), probe.pid);
  if (!probe.is_optional) {
    PX_RETURN_IF_ERROR(status);
  }

  if (status.ok()) {
    uprobes_.push_back(probe);
    ++num_attached_uprobes_;
  }
  return Status::OK();
}

Status BCCWrapper::AttachSamplingProbe(const SamplingProbeSpec& probe) {
  if (replaying_) {
    return Status::OK();
  }

  constexpr uint64_t kNanosPerMilli = 1000 * 1000;
  const uint64_t sample_period = probe.period_millis * kNanosPerMilli;
  // A sampling probe is just a PerfEventProbe, where the perf event is a clock counter.
  // When a requisite number of clock samples occur, the kernel will trigger the BPF code.
  // By specifying a frequency, the kernel will attempt to adjust the threshold to achieve
  // the desired sampling frequency.
  PerfEventSpec perf_event_spec{.type = PERF_TYPE_SOFTWARE,
                                .config = PERF_COUNT_SW_CPU_CLOCK,
                                .probe_fn = probe.probe_fn,
                                .sample_period = sample_period};

  return AttachPerfEvent(perf_event_spec);
}

Status BCCWrapper::AttachKProbes(const ArrayView<KProbeSpec>& probes) {
  for (const KProbeSpec& p : probes) {
    PX_RETURN_IF_ERROR(AttachKProbe(p));
  }
  return Status::OK();
}

Status BCCWrapper::AttachTracepoints(const ArrayView<TracepointSpec>& probes) {
  for (const TracepointSpec& spec : probes) {
    PX_RETURN_IF_ERROR(AttachTracepoint(spec));
  }
  return Status::OK();
}

Status BCCWrapper::AttachUProbes(const ArrayView<UProbeSpec>& probes) {
  for (const UProbeSpec& p : probes) {
    PX_RETURN_IF_ERROR(AttachUProbe(p));
  }
  return Status::OK();
}

Status BCCWrapper::AttachSamplingProbes(const ArrayView<SamplingProbeSpec>& probes) {
  for (const SamplingProbeSpec& p : probes) {
    PX_RETURN_IF_ERROR(AttachSamplingProbe(p));
  }
  return Status::OK();
}

// This will replace the XDP program previously-attached on the the same device.
// Newer kernel allows attaching multiple XDP programs on the same device:
// https://lwn.net/Articles/801478/
Status BCCWrapper::AttachXDP(const std::string& dev_name, const std::string& fn_name) {
  if (replaying_) {
    return Status::OK();
  }

  int fn_fd = -1;
  ebpf::StatusTuple load_status = bpf_.load_func(fn_name, BPF_PROG_TYPE_XDP, fn_fd);

  if (!load_status.ok()) {
    return StatusAdapter(load_status);
  }

  int res_fd = bpf_attach_xdp(dev_name.c_str(), fn_fd, /*flags*/ 0);

  if (res_fd < 0) {
    bpf_.unload_func(fn_name);
    return error::Internal("Unable to attach xdp program for device $0 using $1, errorno: $2",
                           dev_name, fn_name, res_fd);
  }

  return Status::OK();
}

// TODO(PL-1294): This can fail in rare cases. See the cited issue. Find the root cause.
Status BCCWrapper::DetachKProbe(const KProbeSpec& probe) {
  VLOG(1) << "Detaching kprobe: " << probe.ToString();
  if (!replaying_) {
    PX_RETURN_IF_ERROR(bpf_.detach_kprobe(GetKProbeTargetName(probe),
                                          static_cast<bpf_probe_attach_type>(probe.attach_type)));
  }
  --num_attached_kprobes_;
  return Status::OK();
}

Status BCCWrapper::DetachUProbe(const UProbeSpec& probe) {
  VLOG(1) << "Detaching uprobe " << probe.ToString();

  if (!replaying_) {
    if (fs::Exists(probe.binary_path)) {
      PX_RETURN_IF_ERROR(bpf_.detach_uprobe(probe.binary_path, probe.symbol, probe.address,
                                            static_cast<bpf_probe_attach_type>(probe.attach_type),
                                            probe.pid));
    }
  }
  --num_attached_uprobes_;
  return Status::OK();
}

Status BCCWrapper::DetachTracepoint(const TracepointSpec& probe) {
  VLOG(1) << "Detaching tracepoint " << probe.ToString();

  if (!replaying_) {
    PX_RETURN_IF_ERROR(bpf_.detach_tracepoint(probe.tracepoint));
  }

  --num_attached_tracepoints_;
  return Status::OK();
}

void BCCWrapper::DetachKProbes() {
  for (const auto& p : kprobes_) {
    auto res = DetachKProbe(p);
    LOG_IF(ERROR, !res.ok()) << res.msg();
  }
  kprobes_.clear();
}

void BCCWrapper::DetachUProbes() {
  for (const auto& p : uprobes_) {
    auto res = DetachUProbe(p);
    LOG_IF(ERROR, !res.ok()) << res.msg();
  }
  uprobes_.clear();
}

void BCCWrapper::DetachTracepoints() {
  for (const auto& t : tracepoints_) {
    auto res = DetachTracepoint(t);
    LOG_IF(ERROR, !res.ok()) << res.msg();
  }
  tracepoints_.clear();
}

namespace {
::px::stirling::rr::BPFEvents recorded_events_;
::px::stirling::rr::BPFEvents playback_events_;
bool playback_complete_ = false;
bool recording_written_ = false;
int playback_event_idx_ = 0;
}  // namespace

void BCCWrapper::SetRecordingMode() {
  LOG(WARNING) << "BCCWrapper::SetRecordingMode()";
  recording_ = true;
}

void BCCWrapper::SetReplayingMode() {
  LOG(WARNING) << "BCCWrapper::SetReplayingMode()";
  replaying_ = true;

  char const* const pb_file_path = "/home/jps/src/pixielabs.ai/rra-pixie/bpf_events.pb";
  std::fstream input(pb_file_path, std::ios::in | std::ios::binary);
  if (!input) {
    ECHECK(false) << "Could not open file: " << pb_file_path << ".";
  } else if (!playback_events_.ParseFromIstream(&input)) {
    ECHECK(false) << "Could not parse file: " << pb_file_path << ".";
  }
}

void BCCWrapper::WriteProto() {
  if (recording_ && !recording_written_) {
    char const* const file_name = "bpf_events.pb";
    LOG(WARNING) << "Writing BPF events pb to file: " << file_name;

    std::fstream outfile(file_name, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!outfile.is_open()) {
      return;
      // char const* const err_msg = "Failed to open output file: $0.";
      // return error::Internal(absl::Substitute(err_msg, file_name));
    }

    if (!recorded_events_.SerializeToOstream(&outfile)) {
      return;
      // char const* const err_msg = "Failed to write pprof protobuf to file: $0.";
      // return error::Internal(absl::Substitute(err_msg, file_name));
    }
  }
  recording_written_ = true;
  // return Status::OK();
}

void PerfBufferSink(void* cb_cookie, void* data, int data_size) {
  PX_UNUSED(data);
  PX_UNUSED(cb_cookie);
  PX_UNUSED(data_size);
}

void RecordBPFArrayTableGetValueEvent(const std::string& name, const int32_t idx,
                                      const uint32_t data_size, void const* const data) {
  auto event = recorded_events_.add_event()->mutable_array_table_get_value_event();
  auto event_name = event->mutable_name();
  auto event_data = event->mutable_data();

  const std::string data_as_string((char*)data, data_size);

  event->set_idx(idx);
  *event_name = name;
  *event_data = data_as_string;
}

StatusOr<rr::BPFArrayTableGetValueEvent> GetReplayEventBPFArrayTableGetValueEvent(
    const std::string& name, const int32_t idx, const uint32_t data_size) {
  if (playback_complete_) {
    return error::Internal("Playback complete.");
  }

  const auto n_events = playback_events_.event_size();
  if (playback_event_idx_ >= n_events) {
    return error::Internal("playback_event_idx_ wrong.");
  }

  const auto event = playback_events_.event(playback_event_idx_);
  if (!event.has_array_table_get_value_event()) {
    return error::Internal("event not available.");
  }

  const auto array_table_get_value_event = event.array_table_get_value_event();

  if (name != array_table_get_value_event.name()) {
    return error::Internal("Mismatched name.");
  }
  if (idx != array_table_get_value_event.idx()) {
    return error::Internal("Mismatched idx.");
  }
  if (data_size != array_table_get_value_event.data().size()) {
    return error::Internal("Mismatched data size.");
  }
  ++playback_event_idx_;
  return array_table_get_value_event;
}

// template StatusOr<int> ReplayBPFArrayTableGetValueEvent<int>( const std::string& name, const
// int32_t idx ); template StatusOr<unsigned long> ReplayBPFArrayTableGetValueEvent<unsigned long>(
// const std::string& name, const int32_t idx ); template StatusOr<struct buf>
// ReplayBPFArrayTableGetValueEvent<struct buf>( const std::string& name, const int32_t idx );

void RecordPerfBuffer(void* cb_cookie, void* data, int data_size) {
  auto event = recorded_events_.add_event()->mutable_perf_buffer_event();
  auto pb_name = event->mutable_name();
  auto pb_data = event->mutable_data();

  const std::string data_as_string((char*)data, data_size);

  PerfBufferSpec* pb_spec = static_cast<PerfBufferSpec*>(cb_cookie);
  // LOG(WARNING) << absl::StrFormat("Recording from perf buffer: %s, data_size %d, probe_output_fn:
  // 0x%016llx.", pb_spec->name, data_size, uint64_t(pb_spec->probe_output_fn));

  *pb_name = pb_spec->name;
  *pb_data = data_as_string;

  pb_spec->probe_output_fn(pb_spec->cb_cookie, data, data_size);
}

void RecordPerfBufferLoss(void* cb_cookie, uint64_t lost) {
  PerfBufferSpec* pb_spec = static_cast<PerfBufferSpec*>(cb_cookie);
  pb_spec->probe_loss_fn(pb_spec->cb_cookie, lost);
}

Status BCCWrapper::OpenPerfBuffer(const PerfBufferSpec& pb_spec) {
  const int kPageSizeBytes = system::Config::GetInstance().PageSizeBytes();
  int num_pages = IntRoundUpDivide(pb_spec.size_bytes, kPageSizeBytes);

  // Perf buffers must be sized to a power of 2.
  num_pages = IntRoundUpToPow2(num_pages);

  VLOG(1) << absl::Substitute(
      "Opening perf buffer: [$0] [allocated_num_pages=$1 allocated_size_bytes=$2] (per cpu)",
      pb_spec.ToString(), num_pages, num_pages * kPageSizeBytes);

  perf_buffers_.push_back(std::make_unique<PerfBufferSpec>(pb_spec));

  void* cb_cookie = recording_ ? perf_buffers_[num_open_perf_buffers_].get() : pb_spec.cb_cookie;
  auto probe_handler_fn = recording_   ? &RecordPerfBuffer
                          : replaying_ ? &PerfBufferSink
                                       : pb_spec.probe_output_fn;
  auto probe_loss_fn = recording_ ? &RecordPerfBufferLoss : pb_spec.probe_loss_fn;

  replay_cb_fns_[pb_spec.name] = pb_spec.probe_output_fn;

  LOG(WARNING) << absl::StrFormat(
      "Opening perf buffer %d with name: %s, cb_cookie: 0x%016llx, probe_output_fn: 0x%016llx.",
      num_open_perf_buffers_, pb_spec.name, uint64_t(cb_cookie), uint64_t(pb_spec.probe_output_fn));
  if (!replaying_) {
    PX_RETURN_IF_ERROR(bpf_.open_perf_buffer(std::string(pb_spec.name), probe_handler_fn,
                                             probe_loss_fn, cb_cookie, num_pages));
  }
  ++num_open_perf_buffers_;
  return Status::OK();
}

Status BCCWrapper::OpenPerfBuffers(const ArrayView<PerfBufferSpec>& pb_specs) {
  for (const auto& pb_spec : pb_specs) {
    PX_RETURN_IF_ERROR(OpenPerfBuffer(pb_spec));
  }
  return Status::OK();
}

Status BCCWrapper::ClosePerfBuffer(std::unique_ptr<PerfBufferSpec>& perf_buffer) {
  if (replaying_) {
    return Status::OK();
  }
  VLOG(1) << "Closing perf buffer: " << perf_buffer->name;
  PX_RETURN_IF_ERROR(bpf_.close_perf_buffer(std::string(perf_buffer->name)));
  --num_open_perf_buffers_;
  return Status::OK();
}

void BCCWrapper::ClosePerfBuffers() {
  for (auto& p : perf_buffers_) {
    auto res = ClosePerfBuffer(p);
    LOG_IF(ERROR, !res.ok()) << res.msg();
  }
  perf_buffers_.clear();
}

Status BCCWrapper::AttachPerfEvent(const PerfEventSpec& perf_event) {
  if (replaying_) {
    return Status::OK();
  }
  VLOG(1) << absl::Substitute("Attaching perf event:\n   type=$0\n   probe_fn=$1",
                              magic_enum::enum_name(perf_event.type), perf_event.probe_fn);
  PX_RETURN_IF_ERROR(bpf_.attach_perf_event(perf_event.type, perf_event.config,
                                            std::string(perf_event.probe_fn),
                                            perf_event.sample_period, 0));
  perf_events_.push_back(perf_event);
  ++num_attached_perf_events_;
  return Status::OK();
}

Status BCCWrapper::AttachPerfEvents(const ArrayView<PerfEventSpec>& perf_events) {
  for (const PerfEventSpec& p : perf_events) {
    PX_RETURN_IF_ERROR(AttachPerfEvent(p));
  }
  return Status::OK();
}

Status BCCWrapper::DetachPerfEvent(const PerfEventSpec& perf_event) {
  if (replaying_) {
    return Status::OK();
  }
  VLOG(1) << absl::Substitute("Detaching perf event:\n   type=$0\n   probe_fn=$1",
                              magic_enum::enum_name(perf_event.type), perf_event.probe_fn);
  PX_RETURN_IF_ERROR(bpf_.detach_perf_event(perf_event.type, perf_event.config));
  --num_attached_perf_events_;
  return Status::OK();
}

void BCCWrapper::DetachPerfEvents() {
  for (const PerfEventSpec& p : perf_events_) {
    auto res = DetachPerfEvent(p);
    LOG_IF(ERROR, !res.ok()) << res.msg();
  }
  perf_events_.clear();
}

std::string BCCWrapper::GetKProbeTargetName(const KProbeSpec& probe) {
  auto target = std::string(probe.kernel_fn);
  if (probe.is_syscall) {
    target = bpf_.get_syscall_fnname(target);
  }
  return target;
}

void BCCWrapper::PollPerfBuffer(const PerfBufferSpec& pb_spec, const int timeout_ms) {
  // LOG(WARNING) << "BCCWrapper::PollPerfBuffer(), name: " << pb_spec.name << ".";
  if (replaying_) {
    if (!playback_complete_) {
      const auto n_events = playback_events_.event_size();
      while (playback_event_idx_ < n_events) {
        const auto event = playback_events_.event(playback_event_idx_);
        if (event.has_perf_buffer_event()) {
          const auto perf_buffer_event = event.perf_buffer_event();
          const auto data = perf_buffer_event.data();
          const auto name = perf_buffer_event.name();
          if (name == pb_spec.name) {
            // LOG(WARNING) << "BCCWrapper::PollPerfBuffer(), name: " << name << ", data.size(): "
            // << data.size() << ", invoking f() at idx: " << playback_event_idx_ << ".";
            auto f = pb_spec.probe_output_fn;
            f(pb_spec.cb_cookie, (void*)data.data(), data.size());
            ++playback_event_idx_;
            continue;
          }
        }
        break;
      }
    }
  } else {
    auto perf_buffer = bpf_.get_perf_buffer(std::string(pb_spec.name));
    if (perf_buffer != nullptr) {
      perf_buffer->poll(timeout_ms);
    }
  }
}

void BCCWrapper::PollPerfBuffers(int timeout_ms) {
  for (const auto& spec : perf_buffers_) {
    PollPerfBuffer(*spec, timeout_ms);
  }
}

void BCCWrapper::Close() {
  LOG(WARNING) << "BCCWrapper::Close()";
  WriteProto();
  DetachPerfEvents();
  ClosePerfBuffers();
  DetachKProbes();
  DetachUProbes();
  DetachTracepoints();
}

}  // namespace bpf_tools
}  // namespace stirling
}  // namespace px
