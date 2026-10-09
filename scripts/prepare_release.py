"""核对实际 JAR 的版本、许可和测试报告，生成可随发行包下载的摘要。"""

import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
import zipfile


def main():
    root = Path(__file__).resolve().parent.parent
    properties = {}
    for line in (root / "gradle.properties").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            # Gradle 的 Java 属性文件使用 Unicode 转义保存非 ASCII 值。
            properties[key.strip()] = re.sub(
                r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), value.strip()
            )

    # 只接受当前版本的发行文件，防止误上传旧版或开发包。
    filename = "{mod_artifact_id}-forge-{minecraft_version}-{mod_version}.jar".format(**properties)
    jar_path = root / "build" / "libs" / filename
    jars = sorted(jar_path.parent.glob("*.jar"))
    if jars != [jar_path]:
        raise ValueError("发行目录应只包含当前版本的 JAR，请先执行 clean build")

    with zipfile.ZipFile(jar_path) as archive:
        metadata = archive.read("META-INF/mods.toml").decode("utf-8")
        for field, value in {
            "modId": properties["mod_id"],
            "version": properties["mod_version"],
            "displayName": properties["mod_name"],
            "authors": properties["mod_authors"],
        }.items():
            match = re.search(r"^" + field + r'="([^"\n]*)"$', metadata, re.MULTILINE)
            if match is None or match.group(1) != value:
                raise ValueError("JAR 中的模组信息不一致：" + field)
        if properties["mod_description"] not in metadata:
            raise ValueError("JAR 缺少当前中文功能说明，或资源编码有误")
        ranges = re.findall(r'^versionRange="([^"\n]*)"$', metadata, re.MULTILINE)
        if ranges != [properties["forge_version_range"], properties["minecraft_version_range"]]:
            raise ValueError("JAR 中的兼容范围与构建参数不一致")

        # 发行附件同时携带上游的许可原文和来源说明。
        for source in ["LICENCE.txt", "ADDITIONAL-LICENCE.txt", "docs/UPSTREAM.md"]:
            name = Path(source).name
            if archive.read("META-INF/" + name) != (root / source).read_bytes():
                raise ValueError("JAR 中的许可或来源说明不一致：" + name)
        pack = json.loads(archive.read("pack.mcmeta"))
        if pack["pack"]["description"]["text"] != properties["mod_name"] + " resources":
            raise ValueError("资源包显示名称未同步")

    # 汇总现有测试证据；完整联机验收仍单独记录。
    reports = sorted((root / "build" / "test-results" / "test").glob("TEST-*.xml"))
    if not reports:
        raise ValueError("没有测试报告，请先执行 build")
    test_count = 0
    for report in reports:
        suite = ET.parse(report).getroot()
        test_count += int(suite.get("tests", "0"))
        if any(int(suite.get(field, "0")) for field in ["failures", "errors", "skipped"]):
            raise ValueError("测试报告存在失败、错误或跳过：" + report.name)
    if test_count == 0:
        raise ValueError("没有实际执行测试")

    digest = hashlib.sha256(jar_path.read_bytes()).hexdigest()
    (jar_path.parent / "SHA256SUMS").write_text(
        digest + "  " + filename + "\n", encoding="utf-8", newline="\n"
    )
    print(json.dumps({"jar": filename, "sha256": digest, "passed_tests": test_count}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, ET.ParseError) as error:
        print("发行检查失败：" + str(error), file=sys.stderr)
        sys.exit(1)
