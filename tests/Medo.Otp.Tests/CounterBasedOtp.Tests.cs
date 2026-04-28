namespace Tests;

using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Medo;
using System.Text;

[TestClass]
public class CounterBasedOtp_Tests {

    [TestMethod]
    public void CounterBasedOtp_Generate() {
        var o = new CounterBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890"));

        Assert.AreEqual(755224, o.GetCode()); o.Counter++;
        Assert.AreEqual(287082, o.GetCode()); o.Counter++;
        Assert.AreEqual(359152, o.GetCode()); o.Counter++;
        Assert.AreEqual(969429, o.GetCode()); o.Counter++;
        Assert.AreEqual(338314, o.GetCode()); o.Counter++;
        Assert.AreEqual(254676, o.GetCode()); o.Counter++;
        Assert.AreEqual(287922, o.GetCode()); o.Counter++;
        Assert.AreEqual(162583, o.GetCode()); o.Counter++;
        Assert.AreEqual(399871, o.GetCode()); o.Counter++;
        Assert.AreEqual(520489, o.GetCode());
    }

    [TestMethod]
    public void CounterBasedOtp_Validate() {
        var o = new CounterBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890"));

        o.Counter++; Assert.IsTrue(o.IsCodeValid(755224));
        o.Counter++; Assert.IsTrue(o.IsCodeValid(287082));
        o.Counter++; Assert.IsTrue(o.IsCodeValid(359152));
        o.Counter++; Assert.IsTrue(o.IsCodeValid(969429));
        o.Counter++; Assert.IsTrue(o.IsCodeValid(338314));
        o.Counter++; Assert.IsTrue(o.IsCodeValid(254676));
        o.Counter++; Assert.IsTrue(o.IsCodeValid(287922));
        o.Counter++; Assert.IsTrue(o.IsCodeValid(162583));
        o.Counter++; Assert.IsTrue(o.IsCodeValid(399871));
        o.Counter++; Assert.IsTrue(o.IsCodeValid(520489));
    }

    [TestMethod]
    public void CounterBasedOtp_Generate_SHA1() {
        var o = new CounterBasedOtp(Encoding.ASCII.GetBytes("12345678901234567890")) { Digits = 8 };

        o.Counter = 0x0000000000000001;
        Assert.AreEqual(94287082, o.GetCode());

        o.Counter = 0x00000000023523EC;
        Assert.AreEqual(07081804, o.GetCode());

        o.Counter = 0x00000000023523ED;
        Assert.AreEqual(14050471, o.GetCode());

        o.Counter = 0x000000000273EF07;
        Assert.AreEqual(89005924, o.GetCode());

        o.Counter = 0x0000000003F940AA;
        Assert.AreEqual(69279037, o.GetCode());

        o.Counter = 0x0000000027BC86AA;
        Assert.AreEqual(65353130, o.GetCode());
    }

    [TestMethod]
    public void CounterBasedOtp_Validate_SHA1() {
        var o = new CounterBasedOtp(Encoding.ASCII.GetBytes("12345678901234567890")) { Digits = 8 };

        o.Counter = 0x0000000000000001; Assert.IsTrue(o.IsCodeValid(94287082));
        o.Counter = 0x0000000000000002; Assert.IsTrue(o.IsCodeValid(94287082));
        o.Counter = 0x0000000000000003; Assert.IsFalse(o.IsCodeValid(94287082));

        o.Counter = 0x00000000023523EC;
        Assert.IsTrue(o.IsCodeValid("0708 1804"));

        o.Counter = 0x00000000023523ED;
        Assert.IsTrue(o.IsCodeValid(14050471));

        o.Counter = 0x000000000273EF07;
        Assert.IsTrue(o.IsCodeValid(89005924));

        o.Counter = 0x0000000003F940AA;
        Assert.IsTrue(o.IsCodeValid(69279037));

        o.Counter = 0x0000000027BC86AA;
        Assert.IsTrue(o.IsCodeValid(65353130));
    }


    [TestMethod]
    public void Otp_Parameter_Secret_MaxLength() {
        var secret = new byte[1024];
        var otp = new CounterBasedOtp(secret);
        otp.Counter = 42;
        Assert.AreEqual(682871, otp.GetCode());
    }


    [TestMethod]
    public void CounterBasedOtp_GetCodeAsText() {
        var o = new CounterBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890"));
        Assert.AreEqual("755224", o.GetCodeAsText()); o.Counter++;
        Assert.AreEqual("287082", o.GetCodeAsText()); o.Counter++;
        Assert.AreEqual("359152", o.GetCodeAsText()); o.Counter++;
        Assert.AreEqual("969429", o.GetCodeAsText()); o.Counter++;
        Assert.AreEqual("338314", o.GetCodeAsText()); o.Counter++;
        Assert.AreEqual("254676", o.GetCodeAsText()); o.Counter++;
        Assert.AreEqual("287922", o.GetCodeAsText()); o.Counter++;
        Assert.AreEqual("162583", o.GetCodeAsText()); o.Counter++;
        Assert.AreEqual("399871", o.GetCodeAsText()); o.Counter++;
        Assert.AreEqual("520489", o.GetCodeAsText());
    }

    [TestMethod]
    public void CounterBasedOtp_GetCodeAsTextFormatted() {
        var o = new CounterBasedOtp(ASCIIEncoding.ASCII.GetBytes("12345678901234567890"));
        o.Digits = 4; Assert.AreEqual("5224", o.GetCodeAsText()); o.Counter++;
        o.Digits = 5; Assert.AreEqual("87082", o.GetCodeAsText()); o.Counter++;
        o.Digits = 6; Assert.AreEqual("359152", o.GetCodeAsText()); o.Counter++;
        o.Digits = 7; Assert.AreEqual("6960429", o.GetCodeAsText()); o.Counter++;
        o.Digits = 8; Assert.AreEqual("40338314", o.GetCodeAsText()); o.Counter++;
        o.Digits = 9; Assert.AreEqual("868254676", o.GetCodeAsText());

        o.Counter = 0;
        o.Digits = 4; Assert.AreEqual("52 24", o.GetCodeAsText(CodeOutputFormat.Spaced)); o.Counter++;
        o.Digits = 5; Assert.AreEqual("87 082", o.GetCodeAsText(CodeOutputFormat.Spaced)); o.Counter++;
        o.Digits = 6; Assert.AreEqual("359 152", o.GetCodeAsText(CodeOutputFormat.Spaced)); o.Counter++;
        o.Digits = 7; Assert.AreEqual("696 0429", o.GetCodeAsText(CodeOutputFormat.Spaced)); o.Counter++;
        o.Digits = 8; Assert.AreEqual("4033 8314", o.GetCodeAsText(CodeOutputFormat.Spaced)); o.Counter++;
        o.Digits = 9; Assert.AreEqual("868 254 676", o.GetCodeAsText(CodeOutputFormat.Spaced));

        o.Counter = 0;
        o.Digits = 4; Assert.AreEqual("52-24", o.GetCodeAsText(CodeOutputFormat.Dashed)); o.Counter++;
        o.Digits = 5; Assert.AreEqual("87-082", o.GetCodeAsText(CodeOutputFormat.Dashed)); o.Counter++;
        o.Digits = 6; Assert.AreEqual("359-152", o.GetCodeAsText(CodeOutputFormat.Dashed)); o.Counter++;
        o.Digits = 7; Assert.AreEqual("696-0429", o.GetCodeAsText(CodeOutputFormat.Dashed)); o.Counter++;
        o.Digits = 8; Assert.AreEqual("4033-8314", o.GetCodeAsText(CodeOutputFormat.Dashed)); o.Counter++;
        o.Digits = 9; Assert.AreEqual("868-254-676", o.GetCodeAsText(CodeOutputFormat.Dashed));
    }

}
