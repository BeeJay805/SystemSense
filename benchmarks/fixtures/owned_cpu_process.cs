using System;
using System.Threading;

// Evaluator-owned process only. A parent bounds lifetime and pins it to one CPU.
class OwnedCpuProcess {
    static volatile int sink;

    static void Main(string[] args) {
        bool busy = args.Length == 1 && args[0] == "busy";
        while (true) {
            if (busy) {
                int value = sink;
                for (int i = 0; i < 1000000; i++)
                    value = unchecked(value * 1664525 + 1013904223);
                sink = value;
            } else {
                Thread.Sleep(100);
            }
        }
    }
}
