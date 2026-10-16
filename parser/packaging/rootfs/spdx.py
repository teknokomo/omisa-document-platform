#!/usr/bin/env python3
import csv, hashlib, json, sys, uuid
rows = list(csv.reader(open(sys.argv[1]), delimiter='\t'))
hashes = {}
for line in open(sys.argv[2]):
    digest, name = line.split(None, 1); hashes[name.strip()] = digest
packages=[]
for name, version, arch in rows:
    packages.append({
      "SPDXID":"SPDXRef-Package-"+hashlib.sha256(name.encode()).hexdigest()[:16],
      "name":name,"versionInfo":version,"downloadLocation":"NOASSERTION",
      "filesAnalyzed":False,"supplier":"Organization: Ubuntu",
      "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
        "referenceLocator":f"pkg:deb/ubuntu/{name}@{version}?arch={arch}"}]
    })
doc={"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT",
 "name":"omisa-parser-rootfs","documentNamespace":"urn:uuid:"+str(uuid.uuid4()),
 "creationInfo":{"creators":["Tool: omisa-rootfs-spdx.py"],"created":"1970-01-01T00:00:00Z"},
 "packages":packages,"annotations":[{"annotationType":"OTHER","annotator":"Tool: omisa-rootfs-spdx.py",
 "annotationDate":"1970-01-01T00:00:00Z","comment":"Downloaded deb SHA256: "+json.dumps(hashes,sort_keys=True)}]}
json.dump(doc,sys.stdout,indent=2,sort_keys=True); print()
