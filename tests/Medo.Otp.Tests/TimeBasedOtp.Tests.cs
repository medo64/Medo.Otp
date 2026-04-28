namespace Tests;

using System;
using System.Text;
using Medo;
using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class TimeBasedOtp_Tests {

    #region TOTP/6

    [TestMethod]
    public void TimeBasedOtp_Generate6_SHA1() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890")) {
            Digits = 6
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.AreEqual(287082, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.AreEqual(081804, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.AreEqual(050471, o.GetCode());
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.AreEqual(005924, o.GetCode());
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(279037, o.GetCode());
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(353130, o.GetCode());

        o.Time = new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc); Assert.AreEqual(287082, o.GetCode());
        o.Time = new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc); Assert.AreEqual(081804, o.GetCode());
        o.Time = new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc); Assert.AreEqual(050471, o.GetCode());
        o.Time = new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc); Assert.AreEqual(005924, o.GetCode());
        o.Time = new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc); Assert.AreEqual(279037, o.GetCode());
        o.Time = new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc); Assert.AreEqual(353130, o.GetCode());

        o.Time = new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc).ToLocalTime(); Assert.AreEqual(287082, o.GetCode());
        o.Time = new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc).ToLocalTime(); Assert.AreEqual(081804, o.GetCode());
        o.Time = new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc).ToLocalTime(); Assert.AreEqual(050471, o.GetCode());
        o.Time = new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc).ToLocalTime(); Assert.AreEqual(005924, o.GetCode());
        o.Time = new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc).ToLocalTime(); Assert.AreEqual(279037, o.GetCode());
        o.Time = new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc).ToLocalTime(); Assert.AreEqual(353130, o.GetCode());
    }

    [TestMethod]
    public void TimeBasedOtp_Validate6_SHA1() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890")) {
            Digits = 6
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(287082));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(081804));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(050471));
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(005924));
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(279037));
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(353130));
    }


    [TestMethod]
    public void TimeBasedOtp_Generate6_SHA256() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012")) {
            Algorithm = OneTimePasswordAlgorithm.Sha256,
            Digits = 6
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.AreEqual(119246, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.AreEqual(084774, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.AreEqual(062674, o.GetCode());
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.AreEqual(819424, o.GetCode());
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(698825, o.GetCode());
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(737706, o.GetCode());
    }

    [TestMethod]
    public void TimeBasedOtp_Validate6_SHA256() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012")) {
            Algorithm = OneTimePasswordAlgorithm.Sha256,
            Digits = 6
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(119246));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(084774));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(062674));
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(819424));
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(698825));
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(737706));
    }


    [TestMethod]
    public void TimeBasedOtp_Generate6_SHA512() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234")) {
            Algorithm = OneTimePasswordAlgorithm.Sha512,
            Digits = 6
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.AreEqual(693936, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.AreEqual(091201, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.AreEqual(943326, o.GetCode());
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.AreEqual(441116, o.GetCode());
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(618901, o.GetCode());
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(863826, o.GetCode());
    }

    [TestMethod]
    public void TimeBasedOtp_Validate6_SHA512() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234")) {
            Algorithm = OneTimePasswordAlgorithm.Sha512,
            Digits = 6
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(693936));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(091201));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(943326));
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(441116));
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(618901));
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(863826));
    }

    #endregion


    #region TOTP/8

    [TestMethod]
    public void TimeBasedOtp_Generate_SHA1() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890")) {
            Digits = 8
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.AreEqual(94287082, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.AreEqual(07081804, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.AreEqual(14050471, o.GetCode());
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.AreEqual(89005924, o.GetCode());
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(69279037, o.GetCode());
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(65353130, o.GetCode());
    }

    [TestMethod]
    public void TimeBasedOtp_Validate_SHA1() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890")) {
            Digits = 8
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(94287082));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(07081804));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(14050471));
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(89005924));
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(69279037));
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(65353130));
    }


    [TestMethod]
    public void TimeBasedOtp_Generate_SHA256() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012")) {
            Algorithm = OneTimePasswordAlgorithm.Sha256,
            Digits = 8
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.AreEqual(46119246, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.AreEqual(68084774, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.AreEqual(67062674, o.GetCode());
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.AreEqual(91819424, o.GetCode());
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(90698825, o.GetCode());
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(77737706, o.GetCode());
    }

    [TestMethod]
    public void TimeBasedOtp_Validate_SHA256() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890123456789012")) {
            Algorithm = OneTimePasswordAlgorithm.Sha256,
            Digits = 8
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(46119246));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(68084774));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(67062674));
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(91819424));
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(90698825));
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(77737706));
    }


    [TestMethod]
    public void TimeBasedOtp_Generate_SHA512() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234")) {
            Algorithm = OneTimePasswordAlgorithm.Sha512,
            Digits = 8
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.AreEqual(90693936, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.AreEqual(25091201, o.GetCode());
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.AreEqual(99943326, o.GetCode());
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.AreEqual(93441116, o.GetCode());
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(38618901, o.GetCode());
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.AreEqual(47863826, o.GetCode());
    }

    [TestMethod]
    public void TimeBasedOtp_Validate_SHA512() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234")) {
            Algorithm = OneTimePasswordAlgorithm.Sha512,
            Digits = 8
        };

        o.Time = new DateTimeOffset(1970, 01, 01, 01, 00, 59, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(90693936));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 29, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(25091201));
        o.Time = new DateTimeOffset(2005, 03, 18, 02, 58, 31, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(99943326));
        o.Time = new DateTimeOffset(2009, 02, 14, 00, 31, 30, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(93441116));
        o.Time = new DateTimeOffset(2033, 05, 18, 04, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(38618901));
        o.Time = new DateTimeOffset(2603, 10, 11, 12, 33, 20, TimeSpan.FromHours(1)); Assert.IsTrue(o.IsCodeValid(47863826));
    }

    #endregion


    [TestMethod]
    public void Otp_Parameter_Secret_MaxLength() {
        var secret = new byte[1024];
        var otp = new TimeBasedOtp(secret);
        otp.Time = DateTimeOffset.UnixEpoch; Assert.AreEqual(599555, otp.GetCode());
    }

    [TestMethod]
    public void TimeBasedOtp_GetCodeAsText() {
        var o = new TimeBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890"));
        o.Time = new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc); Assert.AreEqual("287082", o.GetCodeAsText());
        o.Time = new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc); Assert.AreEqual("081804", o.GetCodeAsText());
        o.Time = new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc); Assert.AreEqual("050471", o.GetCodeAsText());
        o.Time = new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc); Assert.AreEqual("005924", o.GetCodeAsText());
        o.Time = new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc); Assert.AreEqual("279037", o.GetCodeAsText());
        o.Time = new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc); Assert.AreEqual("353130", o.GetCodeAsText());
        o.Time = new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc); Assert.AreEqual("287 082", o.GetCodeAsText(CodeOutputFormat.Spaced));
        o.Time = new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc); Assert.AreEqual("081 804", o.GetCodeAsText(CodeOutputFormat.Spaced));
        o.Time = new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc); Assert.AreEqual("050 471", o.GetCodeAsText(CodeOutputFormat.Spaced));
        o.Time = new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc); Assert.AreEqual("005 924", o.GetCodeAsText(CodeOutputFormat.Spaced));
        o.Time = new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc); Assert.AreEqual("279 037", o.GetCodeAsText(CodeOutputFormat.Spaced));
        o.Time = new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc); Assert.AreEqual("353 130", o.GetCodeAsText(CodeOutputFormat.Spaced));
        o.Time = new DateTime(1970, 01, 01, 00, 00, 59, DateTimeKind.Utc); Assert.AreEqual("287-082", o.GetCodeAsText(CodeOutputFormat.Dashed));
        o.Time = new DateTime(2005, 03, 18, 01, 58, 29, DateTimeKind.Utc); Assert.AreEqual("081-804", o.GetCodeAsText(CodeOutputFormat.Dashed));
        o.Time = new DateTime(2005, 03, 18, 01, 58, 31, DateTimeKind.Utc); Assert.AreEqual("050-471", o.GetCodeAsText(CodeOutputFormat.Dashed));
        o.Time = new DateTime(2009, 02, 13, 23, 31, 30, DateTimeKind.Utc); Assert.AreEqual("005-924", o.GetCodeAsText(CodeOutputFormat.Dashed));
        o.Time = new DateTime(2033, 05, 18, 03, 33, 20, DateTimeKind.Utc); Assert.AreEqual("279-037", o.GetCodeAsText(CodeOutputFormat.Dashed));
        o.Time = new DateTime(2603, 10, 11, 11, 33, 20, DateTimeKind.Utc); Assert.AreEqual("353-130", o.GetCodeAsText(CodeOutputFormat.Dashed));
    }

    [TestMethod]
    public void TimeBasedOtp_CounterChangesTime() {
        var o = new TimeBasedOtp("abcd");
        o.Counter = 56802240;
        Assert.AreEqual(new DateTimeOffset(2024, 01, 01, 00, 00, 00, TimeSpan.Zero), o.Time);
        Assert.AreEqual(742037, o.GetCode());
    }


}
