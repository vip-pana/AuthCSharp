# Authentication Project - First Step
This is the first step of the authz project.

In this branch of the solution the project are two api:
### Signin
 The Signin API allows users to register by submitting a set of data from the client. It's important to note that the registration details are not stored in a traditional database but are instead maintained in an array of users within the application.

### Login
Once registered using the Signin API, the Login API enables users to verify their credentials. It checks if the user is registered based on the data saved during the registration process.



#### Features
- **Secure Password Storage**: The users' passwords are securely stored using cryptographic hashing. The project utilizes the BCrypt library to ensure the protection of user credentials.
