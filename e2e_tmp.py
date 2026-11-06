import sys, pathlib
from tests import fixtures
from ipasign import cli
root = pathlib.Path(sys.argv[1])
key, cert = fixtures.make_identity()
p12 = root / "id.p12"; p12.write_bytes(fixtures.make_p12(key, cert, password="secret"))
prof = root / "profile.mobileprovision"; prof.write_bytes(fixtures.make_profile(certificates=[cert]))
app = fixtures.make_app_dir(str(root / "src"), bundle_id="com.example.demo")
ipa = root / "in.ipa"; fixtures.make_ipa(app, str(ipa))
out = root / "out.ipa"
print("### sign"); cli.main(["sign", str(ipa), "-c", str(p12), "-p", "secret", "-m", str(prof), "-o", str(out), "--no-download", "--force"])
print("### info"); cli.main(["info", str(out)])
print("### verify"); cli.main(["verify", str(out)])
print("### profile"); cli.main(["profile", str(prof)])
print("### doctor"); cli.main(["doctor", str(out), "-c", str(p12), "-p", "secret", "-m", str(prof)])
print("### identity"); cli.main(["identity", str(p12), "-p", "secret", "--no-download"])
print("### vault import"); cli.main(["vault", "import", "corp", str(p12), "-m", str(prof), "-p", "secret"])
print("### vault list"); cli.main(["vault", "list"])
print("### vault show"); cli.main(["vault", "show", "corp"])
print("### renew"); cli.main(["renew", "corp", str(out), "-p", "secret", "-o", str(root / "renewed.ipa")])
print("### fetch-certs (uses network, may fail)"); 
