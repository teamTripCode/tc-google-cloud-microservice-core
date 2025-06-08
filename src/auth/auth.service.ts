import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';
import { Request } from 'express';
import { AxiosError } from 'axios';

interface UserPayload {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  roles: string[];
  permissions?: string[];
}

interface TokenValidationResponse {
  valid: boolean;
  user: UserPayload;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) { }

  /**
   * Valida un token contra el microservicio de autenticación
   * Esta es la función principal que necesita este microservicio
   */
  async validateToken(token: string): Promise<UserPayload> {
    try {
      const response = await firstValueFrom(
        this.httpService.get('/auth/validate', {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
        }),
      );

      const data: TokenValidationResponse = response.data;

      if (!data.valid || !data.user) {
        throw new UnauthorizedException('Invalid token response');
      }

      return data.user;
    } catch (error) {
      this.logger.error('Token validation failed', error);

      if (error instanceof AxiosError) {
        if (error.response?.status === 401) {
          throw new UnauthorizedException('Invalid or expired token');
        }
        if (error.response?.status === 403) {
          throw new UnauthorizedException('Token access forbidden');
        }
        if (error.code === 'ECONNREFUSED') {
          throw new UnauthorizedException('Authentication service unavailable');
        }
        if (error.code === 'ETIMEDOUT') {
          throw new UnauthorizedException('Authentication service timeout');
        }
      }

      throw new UnauthorizedException('Token validation failed');
    }
  }

  /**
   * Extrae el token del header Authorization
   */
  extractTokenFromRequest(req: Request): string {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      throw new UnauthorizedException('Authorization header is missing');
    }

    const [type, token] = authHeader.split(' ');

    if (type !== 'Bearer' || !token) {
      throw new UnauthorizedException('Invalid authorization header format. Expected: Bearer <token>');
    }

    return token;
  }

  /**
   * Método helper para validar permisos específicos
   */
  hasPermission(user: UserPayload, requiredPermission: string): boolean {
    return user.permissions?.includes(requiredPermission) || false;
  }

  /**
   * Método helper para validar roles específicos
   */
  hasRole(user: UserPayload, requiredRole: string): boolean {
    return user.roles?.includes(requiredRole) || false;
  }

  /**
   * Método helper para validar múltiples roles (OR)
   */
  hasAnyRole(user: UserPayload, requiredRoles: string[]): boolean {
    return requiredRoles.some(role => user.roles?.includes(role)) || false;
  }

  /**
   * Método helper para validar múltiples roles (AND)
   */
  hasAllRoles(user: UserPayload, requiredRoles: string[]): boolean {
    return requiredRoles.every(role => user.roles?.includes(role)) || false;
  }
}