using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Abstractions;

/// <summary>
/// Fluent registration seam returned by <c>AddKlassdAuth(...)</c>. Storage adapters and modules
/// extend this (e.g. <c>.UseSqlite(...)</c>, <c>.UsePostgres(...)</c>, <c>.UseMongoDb(...)</c>),
/// mirroring the Klassd <c>ICmsBuilder</c> pattern.
/// </summary>
public interface IAuthBuilder
{
    IServiceCollection Services { get; }
}
