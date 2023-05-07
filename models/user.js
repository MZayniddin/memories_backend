import mongoose from "mongoose";

const userSchema = mongoose.Schema({
    id: String,
    name: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
});

export default mongoose.model("User", userSchema);
