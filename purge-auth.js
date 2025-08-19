require('dotenv').config();
const { Sequelize } = require('sequelize');

// Database configuration
const sequelize = new Sequelize(process.env.DATABASE_URL || 'postgres://localhost:5432/auth_service', {
  dialect: 'postgres',
  protocol: 'postgres',
  logging: console.log,
  dialectOptions: {
    ssl: process.env.NODE_ENV === 'production' ? {
      require: true,
      rejectUnauthorized: false
    } : false
  }
});

async function purgeAuthData() {
  try {
    console.log('Connecting to database...');
    await sequelize.authenticate();
    console.log('Database connection established successfully.');

    console.log('Starting auth data purge...');
    
    // Delete all users
    const deletedUsers = await sequelize.query('TRUNCATE TABLE users RESTART IDENTITY CASCADE');
    
    console.log('Successfully purged all user data');
    console.log('Auth data purge completed successfully');
    
    await sequelize.close();
    process.exit(0);
  } catch (error) {
    console.error('Error purging auth data:', error);
    process.exit(1);
  }
}

// Run the purge
purgeAuthData(); 