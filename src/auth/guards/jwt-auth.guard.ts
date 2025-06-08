import {
    Injectable,
    CanActivate,
    ExecutionContext,
    UnauthorizedException,
    Logger
} from '@nestjs/common';
import { AuthService } from '../auth.service';

export interface AuthenticatedRequest extends Request {
    user: {
        id: string;
        email: string;
        firstName: string;
        lastName: string;
        roles: string[];
        permissions?: string[];
    };
}

@Injectable()
export class JwtAuthGuard implements CanActivate {
    private readonly logger = new Logger(JwtAuthGuard.name);

    constructor(private readonly authService: AuthService) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();

        try {
            // Extraer token del request
            const token = this.authService.extractTokenFromRequest(request);

            // Validar token contra el microservicio de auth
            const userPayload = await this.authService.validateToken(token);

            // Agregar información del usuario al request
            request.user = userPayload;

            this.logger.debug(`User ${userPayload.email} authenticated successfully`);

            return true;
        } catch (error) {
            this.logger.warn(`Authentication failed: ${error.message}`);
            throw new UnauthorizedException(error.message || 'Authentication failed');
        }
    }
}