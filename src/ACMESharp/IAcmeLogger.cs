using System;

namespace ACMESharp
{
    public interface IAcmeLogger
    {
        void Debug(string message, params object?[] items);
        void Error(Exception? ex, string message, params object?[] items);
        void Error(string message, params object?[] items);
        void Information(string message, params object?[] items);
        void Verbose(string message, params object?[] items);
        void Warning(Exception? ex, string message, params object?[] items);
        void Warning(string message, params object?[] items);
    }
}
