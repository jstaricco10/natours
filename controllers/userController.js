const User = require('../models/userModel');
const APIFeatures = require('../utils/apiFeatures');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

exports.getAllUsers = catchAsync( async(req, res, next) => {
  const users = await User.find();

  // SEND RESPONSE
  res.status(200).json({
    status: 'success',
    result: users.length,
    time: req.requestTime,
    data: {
      users,
    },
  });
});
  
exports.createUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'Route not yet difined'
  });
};
  
exports.getUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'Route not yet difined'
  });
};
exports.updateUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'Route not yet difined'
  });
};
exports.deleteUser = (req, res) => {
  res.status(500).json({
    status: 'error',
    message: 'Route not yet difined'
  });
};