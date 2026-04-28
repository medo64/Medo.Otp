namespace Medo;

using System;

/// <summary>
/// Formatting options for code.
/// </summary>
[Flags()]
public enum CodeOutputFormat {
    /// <summary>
    /// Code will be outputed as string.
    /// </summary>
    None = 0,
    /// <summary>
    /// Code will be split into similarly sized parts separated by spaces.
    /// </summary>
    Spaced = 1,
    /// <summary>
    /// Code will be split into similarly sized parts separated by spaces.
    /// </summary>
    Dashed = 2,
}
