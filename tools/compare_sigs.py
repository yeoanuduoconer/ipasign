import sys
import zipfile

sys.path.insert(0, r"C:\Users\you\source\repos\ipasign")
from ipasign import macho


def describe(path, label):
    print("=" * 20, label)
    archive = zipfile.ZipFile(path)
    names = archive.namelist()
    main = next(n for n in names if n.endswith(".app/Dynamix"))
    framework = next(n for n in names if n.endswith("/UnityFramework"))
    for kind, name in (("main", main), ("framework", framework)):
        data = archive.read(name)
        layout = macho.parse_slice_layout(data)
        signature = macho.read_signatures(data)[0]
        cd = signature.code_directory
        blob_bytes = data[layout.code_sig.dataoff:layout.code_sig.dataoff + layout.code_sig.datasize]
        print(f"[{kind}] file={len(data)} codeLimit={cd.code_limit} lc_datasize={layout.code_sig.datasize} "
              f"sig_area={len(blob_bytes)}")
        print(f"   CD v={cd.version:#x} hash={cd.hash_type} nspecial={cd.n_special} flags={cd.flags:#x}")
        print(f"   execSeg={cd.exec_seg} slots={sorted(hex(k) for k in signature.blobs)}")
        for slot in (5, 7):
            blob = signature.blobs.get(slot)
            if blob:
                print(f"   slot{slot} len={len(blob)}")
    resources = [n for n in names if n.endswith(".app/_CodeSignature/CodeResources")]
    if resources:
        payload = archive.read(resources[0])
        print(f"[CodeResources] size={len(payload)}")

    provision = archive.read(next(n for n in names if n.endswith(".app/embedded.mobileprovision")))
    print(f"[profile] size={len(provision)}")


for path, label in [
    (r"E:\tools\ipasign\diff\zsign-out.ipa", "zsign"),
    (r"C:\Users\you\source\repos\ipasign\out.ipa", "ipasign"),
]:
    describe(path, label)
