import path from 'path';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import core from '@bubblewrap/core';

const { TwaGenerator, TwaManifest, JdkHelper, AndroidSdkTools, GradleWrapper, ConsoleLog } = core;

const log = new ConsoleLog('build-apk');
const repoRoot = path.resolve('.');
const projectDir = path.join(repoRoot, 'twa-build');

if (existsSync(projectDir)) {
  await fs.rm(projectDir, { recursive: true, force: true });
}
await fs.mkdir(projectDir, { recursive: true });

const twaManifestPath = path.join(repoRoot, 'twa-manifest.json');
const twaManifest = await TwaManifest.fromFile(twaManifestPath);

twaManifest.signingKey.path = path.resolve(repoRoot, twaManifest.signingKey.path);

const generator = new TwaGenerator();
await generator.createTwaProject(projectDir, twaManifest, log);
await fs.copyFile(twaManifestPath, path.join(projectDir, 'twa-manifest.json'));

const config = {
  jdkPath: process.env.JAVA_HOME,
  androidSdkPath: process.env.ANDROID_HOME,
};
const jdkHelper = new JdkHelper(process, config);
const androidSdkTools = await AndroidSdkTools.create(process, config, jdkHelper, log);

const gradleWrapper = new GradleWrapper(process, androidSdkTools, projectDir);
await gradleWrapper.assembleRelease();

const unsignedApk = path.join(projectDir, 'app', 'build', 'outputs', 'apk', 'release', 'app-release-unsigned.apk');
const alignedApk = path.join(repoRoot, 'app-release-aligned.apk');
const signedApk = path.join(repoRoot, 'app-release-signed.apk');

await androidSdkTools.zipalign(unsignedApk, alignedApk);
await androidSdkTools.apksigner(
  twaManifest.signingKey,
  process.env.BUBBLEWRAP_KEYSTORE_PASSWORD,
  process.env.BUBBLEWRAP_KEY_PASSWORD,
  alignedApk,
  signedApk,
);

console.log('✓ APK firmado: ' + signedApk);
