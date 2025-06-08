import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtAuthGuard implements CanActivate {
    constructor(private readonly authService: AuthService) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        try {
            const token = await this.authService.extractTokenFromRequest(request);
            const payload = await this.authService.validateToken(token);
            request.user = payload.user;
            return true;
        } catch (error) {
            throw new UnauthorizedException(error.message || 'Invalid token');
        }
    }
}