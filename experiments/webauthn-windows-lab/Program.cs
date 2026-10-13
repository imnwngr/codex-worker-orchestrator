using WebAuthn.WindowsLab;

Console.WriteLine("INTEROPERABILITY LAB — NO APPROVAL");
Console.WriteLine("Fake native API only. No credentials, signatures, prompts, or network.");
Console.WriteLine();

var failures = await LabTests.RunAsync();
Console.WriteLine();
Console.WriteLine($"{LabTests.Count - failures}/{LabTests.Count} fake-only tests passed.");
return failures == 0 ? 0 : 1;
