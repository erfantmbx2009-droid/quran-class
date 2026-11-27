const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

initializeApp();
const db = getFirestore();
const ADMIN_SETUP_CODE = defineSecret("ADMIN_SETUP_CODE");
const PROJECT_ID = "quran-calss-604db";
const EMAIL_DOMAIN = `@${PROJECT_ID}.firebaseapp.com`;
const REGION = "europe-west1";

function cleanUsername(value) {
  return String(value || "").trim().toLowerCase();
}
function validUsername(value) {
  return /^[a-z0-9_]{3,24}$/.test(value);
}
function validPassword(value) {
  return typeof value === "string" && value.length >= 8 && value.length <= 128;
}
function requireRole(request, roles) {
  if (!request.auth) throw new HttpsError("unauthenticated", "ابتدا وارد حساب شوید.");
  if (!roles.includes(request.auth.token.role)) {
    throw new HttpsError("permission-denied", "اجازه انجام این کار را ندارید.");
  }
}

exports.bootstrapAdmin = onCall(
  { region: REGION, secrets: [ADMIN_SETUP_CODE], enforceAppCheck: false },
  async (request) => {
    const username = cleanUsername(request.data?.username);
    const password = request.data?.password;
    const displayName = String(request.data?.displayName || "").trim().slice(0, 80);
    const setupCode = String(request.data?.setupCode || "");

    if (!setupCode || setupCode !== ADMIN_SETUP_CODE.value()) {
      throw new HttpsError("permission-denied", "کد راه‌اندازی معتبر نیست.");
    }
    if (!validUsername(username) || !validPassword(password) || !displayName) {
      throw new HttpsError("invalid-argument", "نام کاربری، نام نمایشی یا رمز عبور معتبر نیست.");
    }

    const lockRef = db.doc("system/adminBootstrap");
    const usernameRef = db.doc(`usernames/${username}`);
    const lockSnap = await lockRef.get();
    if (lockSnap.exists) throw new HttpsError("failed-precondition", "مدیر اولیه قبلاً ساخته شده است.");

    const email = username + EMAIL_DOMAIN;
    let user;
    try {
      user = await getAuth().createUser({ email, password, displayName, disabled: false });
      await db.runTransaction(async (tx) => {
        const lock = await tx.get(lockRef);
        const name = await tx.get(usernameRef);
        if (lock.exists || name.exists) throw new HttpsError("already-exists", "راه‌اندازی قبلاً انجام شده یا نام کاربری تکراری است.");
        tx.create(lockRef, { uid: user.uid, createdAt: FieldValue.serverTimestamp() });
        tx.create(usernameRef, { uid: user.uid });
        tx.create(db.doc(`users/${user.uid}`), {
          uid: user.uid, username, displayName, role: "admin",
          createdAt: FieldValue.serverTimestamp()
        });
      });
      await getAuth().setCustomUserClaims(user.uid, { role: "admin" });
      return { success: true };
    } catch (error) {
      if (user) {
        const lock = await lockRef.get();
        if (!lock.exists || lock.data()?.uid !== user.uid) {
          await getAuth().deleteUser(user.uid).catch(() => {});
        }
      }
      if (error instanceof HttpsError) throw error;
      throw new HttpsError("internal", "ساخت مدیر اولیه انجام نشد.");
    }
  }
);

exports.createClassAccount = onCall({ region: REGION }, async (request) => {
  requireRole(request, ["admin"]);
  const username = cleanUsername(request.data?.username);
  const password = request.data?.password;
  const displayName = String(request.data?.displayName || "").trim().slice(0, 80);
  const role = request.data?.role;
  if (!validUsername(username) || !validPassword(password) || !displayName ||
      !["student", "teacher"].includes(role)) {
    throw new HttpsError("invalid-argument", "اطلاعات حساب معتبر نیست.");
  }

  const usernameRef = db.doc(`usernames/${username}`);
  const existing = await usernameRef.get();
  if (existing.exists) throw new HttpsError("already-exists", "این نام کاربری قبلاً استفاده شده است.");

  let user;
  try {
    user = await getAuth().createUser({
      email: username + EMAIL_DOMAIN, password, displayName, disabled: false
    });
    await db.runTransaction(async (tx) => {
      const name = await tx.get(usernameRef);
      if (name.exists) throw new HttpsError("already-exists", "این نام کاربری قبلاً استفاده شده است.");
      tx.create(usernameRef, { uid: user.uid });
      tx.create(db.doc(`users/${user.uid}`), {
        uid: user.uid, username, displayName, role,
        createdAt: FieldValue.serverTimestamp()
      });
    });
    await getAuth().setCustomUserClaims(user.uid, { role });
    return { success: true, uid: user.uid };
  } catch (error) {
    if (user) await getAuth().deleteUser(user.uid).catch(() => {});
    if (error instanceof HttpsError) throw error;
    throw new HttpsError("internal", "ساخت حساب انجام نشد.");
  }
});

exports.recordAttendance = onCall({ region: REGION }, async (request) => {
  requireRole(request, ["student"]);
  const uid = request.auth.uid;
  const date = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Tehran", year: "numeric", month: "2-digit", day: "2-digit"
  }).format(new Date()).replaceAll("-", "");
  const ref = db.doc(`attendance/${uid}_${date}`);
  try {
    await ref.create({
      uid, date, status: "present",
      createdAt: FieldValue.serverTimestamp()
    });
    return { success: true, date };
  } catch (error) {
    if (error.code === 6 || error.code === "already-exists") {
      throw new HttpsError("already-exists", "حضور امروز شما قبلاً ثبت شده است.");
    }
    throw new HttpsError("internal", "ثبت حضور انجام نشد.");
  }
});
