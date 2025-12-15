using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using MiniJwt.Core.Models;

namespace MiniJwt.Core.Validators
{
    public class MiniJwtOptionsValidator : IValidateOptions<MiniJwtOptions>
    {
        private const int MinSecretLength = 32;

        public ValidateOptionsResult Validate(string? name, MiniJwtOptions? options)
        {
            if (options is null)
                return ValidateOptionsResult.Fail("MiniJwtOptions must be provided.");

            if (string.IsNullOrWhiteSpace(options.SecretKey))
                return ValidateOptionsResult.Fail("SecretKey is required.");

            if (options.SecretKey.Length < MinSecretLength)
                return ValidateOptionsResult.Fail($"SecretKey is too short. Use at least {MinSecretLength} characters.");

            if (options.ExpirationMinutes <= 0)
                return ValidateOptionsResult.Fail("ExpirationMinutes must be greater than zero.");
            
            if (Regex.IsMatch(options.Issuer, @"^\s+$"))
                return ValidateOptionsResult.Fail("Issuer cannot be whitespace only.");
            
            if (Regex.IsMatch(options.Audience, @"^\s+$"))
                return ValidateOptionsResult.Fail("Audience cannot be whitespace only.");

            if (options.Issuer == options.Audience && !string.IsNullOrEmpty(options.Issuer) || !string.IsNullOrEmpty(options.Audience))
                return ValidateOptionsResult.Fail("Issuer and Audience must be different.");

            return ValidateOptionsResult.Success;
        }
    }
}