import semver from "semver";
import fs from "node:fs/promises";

// Format:
// { releases: { "firefox-<downloadVersion>": { "version": "<version>" }, ... } }
const firefoxVersions = await fetch(
    "https://product-details.mozilla.org/1.0/all.json",
).then((res) => res.json());


const latestMinorVersions = Object.entries(firefoxVersions.releases).reduce(
    (acc, [key, { version }]) => {
        // Firefox only — not thunderbird/devedition/fenix/fennec.
        if (!key.startsWith("firefox-")) {
            return acc;
        }
        // No alphas or betas
        if (version.includes("a") || version.includes("b")) {
            return acc;
        }

        // The release key is the real download version; the `version` field is not.
        const downloadVersion = key.slice("firefox-".length);
        const coerced = semver.coerce(version).toString();

        const major = semver.major(coerced);
        if (major >= 140) {
            if (!acc[major] || semver.gt(coerced, acc[major].version)) {
                acc[major] = { version: coerced, downloadVersion };
            }
        }
        return acc;
    },
    {},
);

// Why does node not have this
async function pathExists(path) {
    try {
        await fs.access(path);
        return true;
    } catch {
        return false;
    }
}

const requiredTargets = [];
const platforms = ["darwin", "linux", "windows"];


for (const { version, downloadVersion } of Object.values(latestMinorVersions)) {
    const path = `fingerprints/firefox/${version}/`;
    if (await pathExists(path)) {
        // Check if all of darwin/, linux/, and windows/ exist, and if not, add to requiredTargets
        for (const platform of platforms) {
            if (!(await pathExists(`${path}${platform}/`))) {
                requiredTargets.push({ version, downloadVersion, platform });
            }
        }
    } else {
        for (const platform of platforms) {
            requiredTargets.push({ version, downloadVersion, platform });
        }
    }
}

const platformToOs = {
    darwin: "macos-15",
    linux: "ubuntu-24.04",
    windows: "windows-2025",
};

// Group the missing platforms by download version so each version emits a single command.
const osByDownloadVersion = new Map();
for (const { downloadVersion, platform } of requiredTargets) {
    if (!osByDownloadVersion.has(downloadVersion)) {
        osByDownloadVersion.set(downloadVersion, []);
    }
    osByDownloadVersion.get(downloadVersion).push(platformToOs[platform]);
}

// Emit one `gh workflow run` per version, with the OSes comma-separated.
for (const [downloadVersion, osList] of osByDownloadVersion) {
    console.log(
        `gh workflow run capture.yml -f browser=firefox -f browser_version=${downloadVersion} -f os=${osList.join(",")}`,
    );
}
