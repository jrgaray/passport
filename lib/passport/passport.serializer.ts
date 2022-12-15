import passport from '@fastify/passport';

export abstract class PassportSerializer {
  abstract serializeUser(user: any, done: any);
  abstract deserializeUser(payload: any, done: any);

  constructor() {
    const passportInstance = this.getPassportInstance();
    passportInstance.registerUserSerializer((user, done) =>
      this.serializeUser(user, done)
    );
    passportInstance.registerUserDeserializer((payload, done) =>
      this.deserializeUser(payload, done)
    );
  }

  getPassportInstance() {
    return passport;
  }
}
