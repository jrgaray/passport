/* eslint-disable @typescript-eslint/no-unused-vars */
import {
  CanActivate,
  ExecutionContext,
  Inject,
  Logger,
  mixin,
  Optional,
  UnauthorizedException
} from '@nestjs/common';
import passport from '@fastify/passport';
import { Type } from './interfaces';
import {
  AuthModuleOptions,
  IAuthModuleOptions
} from './interfaces/auth-module.options';
import { defaultOptions } from './options';
import { memoize } from './utils/memoize.util';

export type IAuthGuard = CanActivate & {
  logIn<TRequest extends { logIn: Function } = any>(
    request: TRequest
  ): Promise<void>;
  handleRequest<TUser = any>(
    err,
    user,
    info,
    context: ExecutionContext,
    status?
  ): TUser;
  getAuthenticateOptions(
    context: ExecutionContext
  ): IAuthModuleOptions | undefined;
};
export const AuthGuard: (type?: string | string[]) => Type<IAuthGuard> =
  memoize(createAuthGuard);

const NO_STRATEGY_ERROR = `In order to use "defaultStrategy", please, ensure to import PassportModule in each place where AuthGuard() is being used. Otherwise, passport won't work correctly.`;

function createAuthGuard(type?: string | string[]): Type<CanActivate> {
  class MixinAuthGuard<TUser = any> implements CanActivate {
    @Optional()
    @Inject(AuthModuleOptions)
    protected options: AuthModuleOptions = {};

    constructor(@Optional() options?: AuthModuleOptions) {
      this.options = options ?? this.options;
      if (!type && !this.options.defaultStrategy) {
        new Logger('AuthGuard').error(NO_STRATEGY_ERROR);
      }
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
      const options = {
        ...defaultOptions,
        ...this.options,
        ...(await this.getAuthenticateOptions(context))
      };
      const [request, response] = [
        this.getRequest(context),
        this.getResponse(context)
      ];

      const pFunc = passportFn(
        type || this.options.defaultStrategy,
        options,
        (req, reply, err, user, info, status) => {
          return this.handleRequest(
            req,
            reply,
            err,
            user,
            info,
            context,
            status
          );
        }
      );
      const user = await (pFunc as any)(request, response);
      console.log({ user });

      request[options.property || defaultOptions.property] = user;
      return true;
    }

    getRequest<T = any>(context: ExecutionContext): T {
      return context.switchToHttp().getRequest();
    }

    getResponse<T = any>(context: ExecutionContext): T {
      return context.switchToHttp().getResponse();
    }

    async logIn<TRequest extends { logIn: Function } = any>(
      request: TRequest
    ): Promise<void> {
      const user = request[this.options.property || defaultOptions.property];
      await new Promise<void>((resolve, reject) =>
        request.logIn(user, (err) => (err ? reject(err) : resolve()))
      );
    }

    handleRequest(req, reply, err, user, info, context, status): TUser {
      if (err || !user) throw err || new UnauthorizedException();
      return user;
    }

    getAuthenticateOptions(
      context: ExecutionContext
    ): Promise<IAuthModuleOptions> | IAuthModuleOptions | undefined {
      return undefined;
    }
  }
  const guard = mixin(MixinAuthGuard);
  return guard;
}

const passportFn = (type, options, callback: Function) =>
  passport.authenticate(
    type,
    options,
    async (request, response, err, user, info, status) => {
      request.authInfo = info;
      return callback(request, response, err, user, info, status);
    }
  );
