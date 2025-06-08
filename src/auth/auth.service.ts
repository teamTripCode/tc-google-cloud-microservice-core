import { Injectable, UnauthorizedException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import { Request } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private readonly httpService: HttpService,
  ) { }

  async validateToken(token: string): Promise<any> {
    try {
      const response = await firstValueFrom(
        this.httpService.post('/auth/validate', {}, {
          headers: { Authorization: `Bearer ${token}` },
        }),
      );
      return response.data;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  async extractTokenFromRequest(req: Request): Promise<string> {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new UnauthorizedException('Authorization header is missing');
    }

    const [type, token] = authHeader.split(' ');
    if (type !== 'Bearer' || !token) {
      throw new UnauthorizedException('Invalid authorization header format');
    }

    return token;
  }
}