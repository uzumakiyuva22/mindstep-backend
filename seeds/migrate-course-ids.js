/*
  seeds/migrate-course-ids.js

  Purpose: Normalize Course._id values that are strings (legacy UUIDs)
  into proper MongoDB ObjectId values, and update related Lesson and Task
  documents that reference the old course id.

  IMPORTANT:
  - BACKUP your database before running this script.
  - This script does not run automatically; run it manually after review:
      node seeds/migrate-course-ids.js
  - It will create new Course documents with new ObjectId _id, update
    lessons/tasks that reference the old id, and then remove the old course
    documents. If you prefer to keep the old docs, edit the script to skip
    the deletion step.

  Notes:
  - This script uses mongoose to connect but operates on raw collections
    to avoid model casting issues.
  - If your DB is a single-node (no transactions), the script runs update
    operations sequentially. For a replica set, you may add a session/txn.
*/

require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  if (!process.env.MONGO_URI) {
    console.error('MONGO_URI is required in environment to run migration.');
    process.exit(1);
  }

  console.log('Connecting to MongoDB...');
  await mongoose.connect(process.env.MONGO_URI, { dbName: process.env.MONGO_DBNAME || undefined });
  const db = mongoose.connection.db;

  const coursesColl = db.collection('courses');
  const lessonsColl = db.collection('lessons');
  const tasksColl = db.collection('tasks');

  const allCourses = await coursesColl.find({}).toArray();
  const stringCourses = allCourses.filter((c) => typeof c._id === 'string');

  if (stringCourses.length === 0) {
    console.log('No courses with string _id found. Nothing to migrate.');
    await mongoose.disconnect();
    return;
  }

  console.log(`Found ${stringCourses.length} course(s) with string _id. Preparing migration.`);
  console.log('*** BACKUP YOUR DATABASE BEFORE PROCEEDING ***');

  // Ask for CLI confirmation
  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((res) => rl.question('Proceed with migration? (yes/no): ', res));
  rl.close();
  if (!answer || answer.toLowerCase() !== 'yes') {
    console.log('Migration aborted by user.');
    await mongoose.disconnect();
    return;
  }

  for (const oldCourse of stringCourses) {
    try {
      const oldId = oldCourse._id;
      const newId = new mongoose.Types.ObjectId();

      // Create new course doc with new ObjectId (copy fields)
      const newCourse = Object.assign({}, oldCourse);
      newCourse._id = newId;

      // Insert new course (if slug unique constraint prevents insert, script will fail)
      await coursesColl.insertOne(newCourse);
      console.log(`Inserted new Course for slug='${newCourse.slug}' with new _id=${newId}`);

      // Update lessons referencing oldId
      const lessonUpdate = await lessonsColl.updateMany({ course_id: oldId }, { $set: { course_id: newId } });
      console.log(`Updated ${lessonUpdate.modifiedCount} lesson(s) from course_id='${oldId}' -> '${newId}'`);

      // Update tasks referencing oldId (if tasks collection exists)
      try {
        const taskUpdate = await tasksColl.updateMany({ course_id: oldId }, { $set: { course_id: newId } });
        console.log(`Updated ${taskUpdate.modifiedCount} task(s) from course_id='${oldId}' -> '${newId}'`);
      } catch (tErr) {
        console.warn('Tasks update error (tasks collection may not exist):', tErr && tErr.message ? tErr.message : tErr);
      }

      // Optionally remove old course doc
      const del = await coursesColl.deleteOne({ _id: oldId });
      console.log(`Deleted old Course doc with _id='${oldId}' (deletedCount=${del.deletedCount})`);
    } catch (err) {
      console.error('Error migrating course', oldCourse && oldCourse.slug ? oldCourse.slug : oldCourse, err && err.stack ? err.stack : err);
    }
  }

  console.log('Migration completed. Disconnecting...');
  await mongoose.disconnect();
}

run().catch((e) => {
  console.error('Migration script failed:', e && e.stack ? e.stack : e);
  process.exit(1);
});
