import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true, 
    },
    email: {
      type: String,
      required: true,
      unique: true, 
      trim: true,
      lowercase: true, 
    },
    password: {
      type: String,
      required: true,
    },
    api: {
      type: String,
    },
  },
  {
    timestamps: true, 
  }
);


export default mongoose.models.Users || mongoose.model("Users", userSchema);
