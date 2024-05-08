import  mongoose from 'mongoose'
const Schema = mongoose.Schema;

const userPlaidSchema = new Schema({
  plaidData: {
    type: Schema.Types.Mixed,
    required: true,
  }, 
  name: {
    type: String,
    required: false, // Optional field
  },
  email: {
    type: String,
    required: false, // Optional field
  }
});

const UserPlaid = mongoose.model("UserPlaid", userPlaidSchema);

export default UserPlaid;