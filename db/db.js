import mongoose from 'mongoose';

const databaseConnection = () => {
  console.log('DB_URL:', process.env.DB_URL); // Log the DB_URL value
  mongoose.connect(process.env.DB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('Error connecting to MongoDB:', err));
};

export default databaseConnection;
