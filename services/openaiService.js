const OpenAI = require("openai");

const client = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

async function askGPT(prompt) {
    try {
        const completion = await client.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [
                { role: "system", content: "You are MindStep AI tutor." },
                { role: "user", content: prompt }
            ]
        });

        return completion.choices[0].message.content;
    } catch (err) {
        console.error("OpenAI Error:", err);
        return "AI Error occurred.";
    }
}

module.exports = { askGPT };
