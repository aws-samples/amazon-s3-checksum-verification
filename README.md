## S3 Checksum Verification

This repo provides a simple mechanism to validate local file integrity against the checksums generated and stored by S3 with the object.

1.	Clone the code from Github and enter the repo:

```
git clone https://github.com/aws-samples/s3-checksum-verification
cd s3-checksum-verification
```

2.	Install the python packages the script needs:

```
pip install requirements.txt
```

3.	Configure AWS cli credentials following this guide.
4.	Run the following command to check file integrity

```
./integrity-check.py  --bucketName <your bucketname> --objectName <folder/objectname-in-s3> --localFileName <local file name>
```

5.	You should see a confirmation confirming the data matches e.g.

```
PASS: Checksum match! - s3Checksum: GgECtUetQSLtGNuZ+FEqrbkJ3712Afvx63E2pzpMKnk= | localChecksum: GgECtUetQSLtGNuZ+FEqrbkJ3712Afvx63E2pzpMKnk=
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

