import { openai } from "eve/models/openai";
import { defineAgent } from "eve";

export default defineAgent({
  model: openai("gpt-5.4"),
  reasoning: "high",
});
