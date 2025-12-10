const Course = require('../models/Course');
const Lesson = require('../models/Lesson');
const Task = require('../models/Task');

async function seedCoursesIfMissing(){
  const existing = await Course.countDocuments({});
  if (existing > 0) {
    console.log('Courses exist — skipping seeding');
    return;
  }

  console.log('Seeding default courses and lessons...');

  async function createCourseWithContent(slug, title, description, template){
    const course = await Course.create({ slug, title, description });
    for (const [index, section] of ['Introduction','Basic','Practice','Project'].entries()){
      const lesson = await Lesson.create({ course_id: course._id, title:`${section} - ${title}`, section, order: index+1, content: `${section} content for ${title}` });
      for (let t=0;t<(template.tasksPerSection||3);t++){
        const tk = template.taskFactory(section, t+1);
        await Task.create({
          course_id: course._id,
          lesson_id: lesson._id,
          title: tk.title,
          description: tk.description,
          starterCode: tk.starterCode,
          language: tk.language,
          expectedOutput: tk.expectedOutput
        });
      }
    }
    console.log(`Seeded course: ${title}`);
  }

  await createCourseWithContent('python','Python Programming','Beginner → Project Python',{
    tasksPerSection: 3,
    taskFactory: (section, idx) => {
      if (section === 'Introduction') return { title:`Python Intro ${idx}`, description:'Print Hello', starterCode:`print("Hello Python")`, language:'python', expectedOutput:'Hello Python' };
      if (section === 'Basic') return { title:`Python Basic ${idx}`, description:'Sum numbers', starterCode:`print(2+3)`, language:'python', expectedOutput:'5' };
      if (section === 'Practice') return { title:`Python Practice ${idx}`, description:'Uppercase', starterCode:`print("hi".upper())`, language:'python', expectedOutput:'HI' };
      return { title:`Python Project ${idx}`, description:'List length', starterCode:`print(len([1,2,3]))`, language:'python', expectedOutput:'3' };
    }
  });

  // Add other courses similarly (JS, HTML, CSS, Java)
  // For speed, add small JS example:
  await createCourseWithContent('javascript','JavaScript Essentials','Learn JS basics and DOM',{
    tasksPerSection: 3,
    taskFactory: (section, idx) => {
      if (section === 'Introduction') return { title:`JS Intro ${idx}`, description:'Console log Hello', starterCode:`console.log("Hello JS")`, language:'javascript', expectedOutput:'Hello JS' };
      if (section === 'Basic') return { title:`JS Basic ${idx}`, description:'Sum numbers', starterCode:`console.log(2+3)`, language:'javascript', expectedOutput:'5' };
      return { title:`JS Practice ${idx}`, description:'Uppercase', starterCode:`console.log("hi".toUpperCase())`, language:'javascript', expectedOutput:'HI' };
    }
  });

  console.log('✔ Seeding done.');
}

module.exports = async function seed(){
  try { await seedCoursesIfMissing(); } catch (e) { console.error('Seed error', e); }
};
