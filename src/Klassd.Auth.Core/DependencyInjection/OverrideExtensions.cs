using Klassd.Auth.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace Klassd.Auth.Core.DependencyInjection;

/// <summary>
/// Lets you override any Klassd.Auth service the way SuperTokens lets you override recipe functions:
/// wrap the default implementation, replace the methods you care about, and call the original for the
/// rest. Pair with the matching <c>…ServiceDecorator</c> base class so you only override one method.
/// </summary>
public static class OverrideExtensions
{
    /// <summary>
    /// Replaces the registered <typeparamref name="TService"/> with a decorator built from the current
    /// implementation. The factory receives the original instance (and the provider) and returns the
    /// wrapper. Stackable — each call wraps the previous registration. Call after <c>AddKlassdAuth(...)</c>.
    /// </summary>
    public static IAuthBuilder Override<TService>(
        this IAuthBuilder auth, Func<TService, IServiceProvider, TService> decorate) where TService : class
    {
        var services = auth.Services;
        var index = LastIndexOf(services, typeof(TService));
        if (index < 0)
            throw new InvalidOperationException(
                $"Cannot override {typeof(TService).Name}: it isn't registered. Call AddKlassdAuth(...) (and any "
                + "module/storage adapter that registers it) before .Override<...>().");

        var original = services[index];
        services[index] = new ServiceDescriptor(
            typeof(TService),
            sp => decorate((TService)CreateOriginal(original, sp), sp),
            original.Lifetime);
        return auth;
    }

    private static int LastIndexOf(IServiceCollection services, Type serviceType)
    {
        for (var i = services.Count - 1; i >= 0; i--)
            if (services[i].ServiceType == serviceType) return i;
        return -1;
    }

    private static object CreateOriginal(ServiceDescriptor d, IServiceProvider sp)
    {
        if (d.ImplementationInstance is not null) return d.ImplementationInstance;
        if (d.ImplementationFactory is not null) return d.ImplementationFactory(sp);
        return ActivatorUtilities.CreateInstance(sp, d.ImplementationType!);
    }
}
