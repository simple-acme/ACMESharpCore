using System;
using System.Net.Http;
using ACMESharp.Protocol.Resources;

namespace ACMESharp.Protocol
{
    public class AcmeProtocolException : Exception
    {
        private Problem? _problem;

        public AcmeProtocolException(HttpResponseMessage response, string message, Problem? problem = null) : base(message)
        {
            Response = response;
            Init(problem);
        }

        private void Init(Problem? problem = null)
        {
            _problem = problem;
            var problemType = _problem?.Type;
            if (!string.IsNullOrEmpty(problemType))
            {
                if (problemType.StartsWith(Problem.StandardProblemTypeNamespace))
                {
                    if (Enum.TryParse(
                        problemType.Substring(Problem.StandardProblemTypeNamespace.Length), 
                        true,
                        out ProblemType pt))
                    {
                        ProblemType = pt;
                    };
                }
            }
        }

        public ProblemType ProblemType { get; private set; } = ProblemType.Unknown;
        public HttpResponseMessage Response { get; private set; }
        public string? ProblemTypeRaw => _problem?.Type;
        public string? ProblemDetail => _problem?.Detail;
        public string? ProblemInstance => _problem?.Instance;
        public int ProblemStatus => _problem?.Status ?? -1;
    }
}
