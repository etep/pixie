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

class ProfilerTest {
  // Our two leaf functions do not share their code, as we had originally intended. Sharing
  // would work like this:
  // leaf2x() { return leaf(5);  }  // Crafted such that leaf(5) does 2x the work of leaf(10).
  // leaf1x() { return leaf(10); }
  // i.e. with a shared parameterized leaf function, leaf1x() and leaf2x() are just pass throughs.
  // Unfortunately, different JVMs inline functions in different ways. Some of them would inline
  // leaf1x and leaf2x and as a result, we were unable to find the expected symbols.

  public static long leaf1x() {
    long s = 0;
    long startTime = System.currentTimeMillis();

    while ((System.currentTimeMillis() - startTime) < 5) {
      s++;
    }
    return s;
  }

  public static long leaf2x() {
    long s = 0;
    long startTime = System.currentTimeMillis();

    while ((System.currentTimeMillis() - startTime) < 10) {
      s++;
    }
    return s;
  }

  public static void main(String[] args) {
    long ntrials = 500000000;
    long update_interval = ntrials / 100000;
    long leaf1xsum = 0;
    long leaf2xsum = 0;

    for(long i=0; i < ntrials; i++) {
      for(long j=0; j < ntrials; j++) {
        // Contrived to do the following:
        // 1. Run for a (really) long time (i.e. until the process is externally killed).
        // 2. Spend twice as much time in leaf2x() vs. leaf1x().
        leaf1xsum = leaf1x();
        leaf2xsum = leaf2x();
        if(j % update_interval == 0) {
          String msg = "Completed %6d trials, leaf1xsum: %d, leaf2xsum: %d.";
          System.out.println(String.format(msg, j, leaf1xsum, leaf2xsum));
        }
      }
    }

    System.out.println(leaf1xsum);
    System.out.println(leaf2xsum);
  }
}
