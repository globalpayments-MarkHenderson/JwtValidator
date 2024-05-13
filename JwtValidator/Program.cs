using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Reflection.Metadata;
using System.Security.Cryptography;
using System.Text;
using CommandLine;
using CommandLine.Text;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

class Program
{
    public class Options
    {
        [Option('j', "jwt", HelpText = "The JWT token to validate.")]
        public string Jwt { get; set; }

        [Option("jwt-file", HelpText = "The file path of the JWT.")]
        public string JwtFile { get; set; }


        [Option('u', "jwks-url", HelpText = "The URL of the JWKS.")]
        public string JwksUrl { get; set; }

        [Option("jwks-json", HelpText = "The JWKS payload.")]
        public string JwksJson { get; set; }
        
        [Option("jwks-file", HelpText = "The file path of a JWKS file.")]
        public string JwksFile { get; set; }

        //[Option("rsa-key", HelpText = "The RSA key (Pem Format).")]
        //public string RsaKey { get; set; }

        [Option("rsa-key-file", HelpText = "The file path of the RSA key in PEM format.")]
        public string RsaKeyFile { get; set; }

        [Option("manual", HelpText = "Use the Manual validation method.")]
        public bool Manual { get; set; }


        [Option('v', "verbose", Default = false, HelpText = "Set output to verbose messages.")]
        public bool Verbose { get; set; }
    }


    static void Main(string[] args)
    {
        var parser = new Parser(with => with.HelpWriter = null);
        var parserResult = parser.ParseArguments<Options>(args);

        parserResult
            .WithParsed<Options>(o =>
            {
                if (string.IsNullOrEmpty(o.Jwt) && string.IsNullOrEmpty(o.JwtFile))
                {
                    Console.WriteLine("Error: You must provide either the 'jwt' or 'jwt-file' option.");
                    DisplayHelp(parserResult);
                    Environment.Exit(1);
                }

                if (string.IsNullOrEmpty(o.JwksUrl) && string.IsNullOrEmpty(o.JwksJson) && string.IsNullOrEmpty(o.JwksFile) && string.IsNullOrEmpty(o.RsaKeyFile))
                {
                    Console.WriteLine("Error: You must provide one of the 'jwks-url', 'jwks-json', 'jwks-file' or 'rsa-key-file' options.");
                    DisplayHelp(parserResult);
                    Environment.Exit(1);
                }

                ValidateJwt(o);
            })
            .WithNotParsed(errs => DisplayHelp(parserResult));
    }

    private static void DisplayHelp<T>(ParserResult<T> result)
    {
        var helpText = HelpText.AutoBuild(result, h => h, e => e);
        Console.WriteLine(helpText);
    }



    static void ValidateJwt(Options options)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var rsa = new RSACryptoServiceProvider();
            RSAParameters? rsaParameters = null;
            JObject jwksJson = null;
            List<JToken> keys = null;

            if (!string.IsNullOrEmpty(options.JwtFile))
            {
                if(options.Verbose)
                {
                    Console.WriteLine($"Reading JWT from file: {options.JwtFile}");
                }
                options.Jwt = File.ReadAllText(options.JwtFile);
            }

            if (!string.IsNullOrEmpty(options.RsaKeyFile))
            {
                if (options.Verbose)
                {
                    Console.WriteLine($"Reading RSA key (PEM format) from file: {options.RsaKeyFile}");
                }
                var pemString = File.ReadAllText(options.RsaKeyFile);
                rsa.ImportFromPem(pemString);                     
            }
            else if (!string.IsNullOrEmpty(options.JwksJson))
            {
                if (options.Verbose)
                {
                    Console.WriteLine($"Parsing JWKS from JSON string: {options.JwksJson}");
                }
                jwksJson = JObject.Parse(options.JwksJson);
                keys = jwksJson["keys"].ToList();
            }
            else if (!string.IsNullOrEmpty(options.JwksFile))
            {
                if (options.Verbose)
                {
                    Console.WriteLine($"Reading JWKS from file: {options.JwksFile}");
                }
                var jwks = File.ReadAllText(options.JwksFile);
                jwksJson = JObject.Parse(jwks);
                keys = jwksJson["keys"].ToList();
            }
            else
            {
                if (options.Verbose)
                {
                    Console.WriteLine($"Reading JWKS from URL: {options.JwksUrl}");
                }
                var httpClient = new HttpClient();
                var jwks = httpClient.GetStringAsync(options.JwksUrl).Result;
                jwksJson = JObject.Parse(jwks);
                keys = jwksJson["keys"].ToList();
            }

            if (keys != null)
            {
                for (int i = 0; i < keys.Count; i++)
                {
                    if (keys[i]["kty"].ToString() == "RSA")
                    {
                        rsaParameters = GetRSAParameters(keys[i]);
                        rsa.ImportParameters(rsaParameters.Value);
                    }
                }
            }

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new RsaSecurityKey(rsa),
                ValidateIssuer = false,
                ValidateAudience = false,       
                ValidateLifetime = false,
            };

            try
            {


                if (options.Manual)
                {
                    if (options.Verbose)
                    {
                        Console.WriteLine("Using manual validation method");
                    }
                    var sha256 = ManualValidation(options, rsa);
                    Console.WriteLine("Token is valid");
                    return;
                }
                else
                { 
                    if (!handler.CanReadToken(options.Jwt))
                    {
                        Console.WriteLine("Token format is not valid");
                        return;
                    }
                    Console.WriteLine("Token format is valid");

                    handler.ValidateToken(options.Jwt, validationParameters, out var validatedToken);
                    var jwt = validatedToken as JwtSecurityToken;

                    if (jwt == null || !jwt.Header.Alg.Equals(SecurityAlgorithms.RsaSha256, StringComparison.InvariantCultureIgnoreCase))
                    {
                        throw new SecurityTokenException("Invalid token");
                    }

                    Console.WriteLine("Token is valid");
                    return;
                }
            }
            catch (SecurityTokenException ste)
            {
                if (options.Verbose)
                {
                    Console.WriteLine($"Token validation failed: {ste.Message}");
                }
                Console.WriteLine("Token validation failed.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Token validation failed: {ex.Message}");
        }
    }

    private static SHA256 ManualValidation(Options options, RSACryptoServiceProvider rsa)
    {
        // Split the JWT into its components
        var parts = options.Jwt.Split('.');
        if (parts.Length != 3)
        {
            throw new ArgumentException("Invalid JWT");
        }
        var sha256 = SHA256.Create();
        var computedHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));

        // Base64Url decode the JWT signature
        var signature = Base64UrlEncoder.DecodeBytes(parts[2]);

        // Verify the signature
        if (!rsa.VerifyHash(computedHash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            throw new SecurityTokenException("Invalid signature");
        }

        return sha256;
    }

    static RSAParameters GetRSAParameters(JToken key)
    {
        var exponent = Base64UrlEncoder.DecodeBytes(key["e"].ToString());
        var modulus = Base64UrlEncoder.DecodeBytes(key["n"].ToString());

        return new RSAParameters { Exponent = exponent, Modulus = modulus };
    }



}
