#include "controller.h"

int main(int argc, char** argv) {
  Controller controller;
  controller.ParseCmdline(argc, argv);

  return 0;
}
