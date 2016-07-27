/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "config.h"

#include <cstdlib>
#include <iostream>

int main(int argc, char **argv) {
  Config cfg;
  if (cfg.ParseArgs(argc, argv) != Config::OK) {
    std::cerr << "Error parsing config arguments\n";
    exit(1);
  }

  auto f1 = cfg.ConfigGet("flag1", int);
  std::cerr << "flag1 " << f1 << std::endl;

  auto f2  = cfg.ConfigGet("flag2", int);
  std::cerr << "flag1 " << f2 << std::endl;

  exit(0);
}
