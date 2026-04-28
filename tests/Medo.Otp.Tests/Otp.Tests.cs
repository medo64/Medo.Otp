namespace Tests;

using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo;
using System.Diagnostics.Metrics;
using System.Threading;

[TestClass]
public class Otp_Tests {

    #region New

    [TestMethod]
    public void Otp_Basic() {
        var totp1 = new TimeBasedOtp();
        var hotp1 = new CounterBasedOtp();

        Assert.AreEqual(20, totp1.GetSecret().Length);
        Assert.AreEqual(20, hotp1.GetSecret().Length);
        Assert.AreNotEqual(BitConverter.ToString(totp1.GetSecret()), BitConverter.ToString(hotp1.GetSecret()));
    }

    [TestMethod]
    public void Otp_InvalidSecretEncoding() {
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            _ = new TimeBasedOtp("@");
        });
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            _ = new CounterBasedOtp("@");
        });
    }

    [TestMethod]
    public void Otp_IgnoreSpacesInSecret() {
        var input = "MZx w6\tyT   bo I=";
        var output = "mzxw6ytboi";

        var totp = new TimeBasedOtp(input);
        Assert.AreEqual(output, totp.GetSecretAsText(SecretOutputFormat.None));

        var hotp = new TimeBasedOtp(input);
        Assert.AreEqual(output, hotp.GetSecretAsText(SecretOutputFormat.None));
    }

    [TestMethod]
    public void Otp_NullSecret() {
        Assert.Throws<ArgumentNullException>(() => {
            _ = new TimeBasedOtp(null as string);
        });
        Assert.Throws<ArgumentNullException>(() => {
            _ = new CounterBasedOtp(null as string);
        });
    }

    #endregion New


    #region Base32

    [TestMethod]
    public void Otp_Secret_Base32_Empty() {
        var input = "";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("", otp.GetSecretAsText());
            Assert.AreEqual("", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_SingleCharacter() {
        var input = "m";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("60", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("ma", otp.GetSecretAsText());
            Assert.AreEqual("ma", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("ma", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("ma======", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("ma== ====", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_TwoCharacters() {
        var input = "my";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("my", otp.GetSecretAsText());
            Assert.AreEqual("my", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("my", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("my======", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("my== ====", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_TwoCharacters_IgnoreCase() {
        var input = "MY======";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("my", otp.GetSecretAsText());
            Assert.AreEqual("my", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("my", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("my======", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("my== ====", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_ThreeCharacters() {
        var input = "mzx";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6E", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxa", otp.GetSecretAsText());
            Assert.AreEqual("mzxa", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxa", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxa====", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxa ====", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_FourCharacters() {
        var input = "mzxq";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxq", otp.GetSecretAsText());
            Assert.AreEqual("mzxq", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxq", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxq====", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxq ====", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_FourCharacters_IgnoreCase() {
        var input = "MZXQ====";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxq", otp.GetSecretAsText());
            Assert.AreEqual("mzxq", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxq", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxq====", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxq ====", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_FiveCharacters() {
        var input = "mzxw6";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6===", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6===", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_FiveCharacters_IgnoreCase() {
        var input = "MZXW6===";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6===", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6===", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_SixCharacters() {
        var input = "mzxw6y";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F-60", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6ya", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6ya", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6ya", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6ya=", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6ya=", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_SevenCharacters() {
        var input = "mzxw6yq";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F-62", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6yq", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6yq", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6yq", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6yq=", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6yq=", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_SevenCharacters_IgnoreCase() {
        var input = "MZXW6YQ=";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F-62", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6yq", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6yq", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6yq", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6yq=", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6yq=", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_EightCharacters() {
        var input = "mzxw6ytb";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F-62-61", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6ytb", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6ytb", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6ytb", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6ytb", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6ytb", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_EightCharacters_IgnoreCase() {
        var input = "MZXW6YTB";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F-62-61", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6ytb", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6ytb", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6ytb", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6ytb", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6ytb", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_NineCharacters() {
        var input = "mzxw6ytbo";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F-62-61-70", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6ytb oa", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6ytboa", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6ytb oa", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6ytboa======", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6ytb oa== ====", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_TenCharacters() {
        var input = "mzxw6ytboi";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F-62-61-72", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6ytb oi", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6ytboi", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6ytb oi", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6ytboi======", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6ytb oi== ====", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_TenCharacters_IgnoreCase() {
        var input = "MZXW6YTBOI======";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("66-6F-6F-62-61-72", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("mzxw 6ytb oi", otp.GetSecretAsText());
            Assert.AreEqual("mzxw6ytboi", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("mzxw 6ytb oi", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("mzxw6ytboi======", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("mzxw 6ytb oi== ====", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    [TestMethod]
    public void Otp_Base32_SixteenCharacters() {
        var input = "jbsw y3dp ehpk 3pxp";
        var totp = new TimeBasedOtp(input);
        var hotp = new TimeBasedOtp(input);
        foreach (var otp in new Otp[] { totp, hotp }) {
            Assert.AreEqual("48-65-6C-6C-6F-21-DE-AD-BE-EF", BitConverter.ToString(otp.GetSecret()));
            Assert.AreEqual("jbsw y3dp ehpk 3pxp", otp.GetSecretAsText());
            Assert.AreEqual("jbswy3dpehpk3pxp", otp.GetSecretAsText(SecretOutputFormat.None));
            Assert.AreEqual("jbsw y3dp ehpk 3pxp", otp.GetSecretAsText(SecretOutputFormat.Spacing));
            Assert.AreEqual("jbswy3dpehpk3pxp", otp.GetSecretAsText(SecretOutputFormat.Padding));
            Assert.AreEqual("jbsw y3dp ehpk 3pxp", otp.GetSecretAsText(SecretOutputFormat.Spacing | SecretOutputFormat.Padding));
        }
    }

    #endregion


    #region Parameters

    [TestMethod]
    public void Otp_Parameter_Digits() {
        var totp = new TimeBasedOtp {
            Digits = 4
        };
        totp.Digits = 9;

        var hotp = new CounterBasedOtp {
            Digits = 4
        };
        hotp.Digits = 9;
    }

    [TestMethod]
    public void Otp_Parameter_Digits_TooShort() {
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            var totp = new TimeBasedOtp {
                Digits = 3
            };
        });
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            var totp = new CounterBasedOtp {
                Digits = 3
            };
        });
    }

    [TestMethod]
    public void Otp_Parameter_Digits_TooLong() {
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            var o = new TimeBasedOtp {
                Digits = 10
            };
        });
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            var o = new CounterBasedOtp {
                Digits = 10
            };
        });
    }

    [TestMethod]
    public void Otp_Parameter_Algorithm() {
        var toto = new TimeBasedOtp {
            Algorithm = OneTimePasswordAlgorithm.Sha1
        };
        toto.Algorithm = OneTimePasswordAlgorithm.Sha256;
        toto.Algorithm = OneTimePasswordAlgorithm.Sha512;

        var hoto = new CounterBasedOtp {
            Algorithm = OneTimePasswordAlgorithm.Sha1
        };
        hoto.Algorithm = OneTimePasswordAlgorithm.Sha256;
        hoto.Algorithm = OneTimePasswordAlgorithm.Sha512;
    }

    [TestMethod]
    public void Otp_Parameter_Algorithm_OutOfRange() {
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            _ = new TimeBasedOtp {
                Algorithm = (OneTimePasswordAlgorithm)3
            };
        });
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            _ = new CounterBasedOtp {
                Algorithm = (OneTimePasswordAlgorithm)3
            };
        });
    }

    [TestMethod]
    public void Otp_Parameter_Secret_TooLong() {
        var secret = new byte[1025];
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            _ = new TimeBasedOtp(secret);
        });
        Assert.Throws<ArgumentOutOfRangeException>(() => {
            _ = new CounterBasedOtp(secret);
        });
    }

    #endregion

}
