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

  await createCourseWithContent('html','HTML Foundations','Build semantic and accessible web pages',{
    tasksPerSection: 3,
    taskFactory: (section, idx) => {
      if (section === 'Introduction') return { title:`HTML Intro ${idx}`, description:'Create basic HTML', starterCode:`<h1>Hello HTML</h1>`, language:'html', expectedOutput:'Hello HTML' };
      if (section === 'Basic') return { title:`HTML Basic ${idx}`, description:'Create paragraphs', starterCode:`<p>This is a paragraph</p>`, language:'html', expectedOutput:'This is a paragraph' };
      if (section === 'Practice') return { title:`HTML Practice ${idx}`, description:'Build forms', starterCode:`<form><input type="text"></form>`, language:'html', expectedOutput:'form' };
      return { title:`HTML Project ${idx}`, description:'Semantic markup', starterCode:`<header><nav></nav></header>`, language:'html', expectedOutput:'header' };
    }
  });

  await createCourseWithContent('css','CSS Styling','Master responsive layouts and animations',{
    tasksPerSection: 3,
    taskFactory: (section, idx) => {
      if (section === 'Introduction') return { title:`CSS Intro ${idx}`, description:'Basic styling', starterCode:`.box { color: blue; }`, language:'css', expectedOutput:'color' };
      if (section === 'Basic') return { title:`CSS Basic ${idx}`, description:'Flexbox layout', starterCode:`.container { display: flex; }`, language:'css', expectedOutput:'flex' };
      if (section === 'Practice') return { title:`CSS Practice ${idx}`, description:'Grid layout', starterCode:`.grid { display: grid; }`, language:'css', expectedOutput:'grid' };
      return { title:`CSS Project ${idx}`, description:'Animations', starterCode:`@keyframes slide { from {} to {} }`, language:'css', expectedOutput:'keyframes' };
    }
  });

  await createCourseWithContent('javascript','JavaScript Essentials','Learn JS basics and DOM',{
    tasksPerSection: 3,
    taskFactory: (section, idx) => {
      if (section === 'Introduction') return { title:`JS Intro ${idx}`, description:'Console log Hello', starterCode:`console.log("Hello JS")`, language:'javascript', expectedOutput:'Hello JS' };
      if (section === 'Basic') return { title:`JS Basic ${idx}`, description:'Sum numbers', starterCode:`console.log(2+3)`, language:'javascript', expectedOutput:'5' };
      if (section === 'Practice') return { title:`JS Practice ${idx}`, description:'Uppercase', starterCode:`console.log("hi".toUpperCase())`, language:'javascript', expectedOutput:'HI' };
      return { title:`JS Project ${idx}`, description:'DOM manipulation', starterCode:`document.getElementById("demo").innerHTML = "Hello"`, language:'javascript', expectedOutput:'Hello' };
    }
  });

  await createCourseWithContent('java','Java Backend Development','Develop backend systems and scalable applications',{
    tasksPerSection: 3,
    taskFactory: (section, idx) => {
      if (section === 'Introduction') return { title:`Java Intro ${idx}`, description:'Print Hello', starterCode:`public class Main { public static void main(String[] args) { System.out.println("Hello Java"); } }`, language:'java', expectedOutput:'Hello Java' };
      if (section === 'Basic') return { title:`Java Basic ${idx}`, description:'Sum numbers', starterCode:`public class Main { public static void main(String[] args) { System.out.println(2+3); } }`, language:'java', expectedOutput:'5' };
      if (section === 'Practice') return { title:`Java Practice ${idx}`, description:'Class creation', starterCode:`public class Main { public static void main(String[] args) { System.out.println("Object"); } }`, language:'java', expectedOutput:'Object' };
      return { title:`Java Project ${idx}`, description:'Collections', starterCode:`public class Main { public static void main(String[] args) { java.util.List<Integer> list = new java.util.ArrayList<>(); System.out.println(list.isEmpty()); } }`, language:'java', expectedOutput:'true' };
    }
  });

  console.log('✔ Seeding done.');
}

module.exports = async function seed(){
  try { await seedCoursesIfMissing(); } catch (e) { console.error('Seed error', e); }
};
