import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import User from "../models/user.js";

export const signin = async (req, res) => {
    const { email, password } = req.body;

    try {
        const existingUser = await User.find({ email });

        if (!existingUser.length)
            return res.status(404).json({ message: "User doesn't exist" });

        const isPasswordCorrect = await bcrypt.compare(
            password,
            existingUser[0].password
        );

        if (!isPasswordCorrect)
            return res.status(400).json({ message: "Invalid credentials" });

        const token = jwt.sign(
            { email: existingUser[0].email, id: existingUser[0]._id },
            "test",
            { expiresIn: "1h" }
        );

        res.status(200).json({ result: existingUser[0], token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const signup = async (req, res) => {
    const { email, password, firstName, lastName, confirmPassword } = req.body;

    try {
        const existingUser = await User.find({ email });

        if (existingUser.length)
            return res.status(400).json({ message: "User already exists" });

        if (password !== confirmPassword)
            return res.status(400).json({ message: "Password don't match" });

        const hashPassword = await bcrypt.hash(password, 10);

        const result = await User.create({
            email,
            password: hashPassword,
            name: `${firstName} ${lastName}`,
        });

        const token = jwt.sign(
            { email: result.email, id: result._id },
            "test",
            { expiresIn: "1h" }
        );

        res.status(200).json({ result, token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
