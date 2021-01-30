const mongoose = require('mongoose');
const dotenv = require('dotenv');


process.on('uncaughtException', err =>{
  console.log('UNCAUGHT EXCEPTION! Shuting down...');
  console.log(err.name, err.message);
  process.exit(1);
});

dotenv.config({ path: './config.env' });

const app = require('./app');

const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);

mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true  // ojo al tejo
  })
  .then(() => {
    console.log('DB connection established!');
  });

const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`App runnig on port ${port} ...`);
});

process.on('unhandledRejection', err => {
  console.log('UNHANDLED REJECTION! Shuting down...');
  console.log(err.name, err.message);
  server.close(() =>{   
    process.exit(1);
  });
});



