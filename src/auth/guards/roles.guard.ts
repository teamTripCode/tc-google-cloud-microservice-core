import {
    Injectable,
    CanActivate,
    ExecutionContext,
    ForbiddenException,
    SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthService } from '../auth.service';
import { AuthenticatedRequest } from './jwt-auth.guard';

export const ROLES_KEY = 'roles';
export const PERMISSIONS_KEY = 'permissions';

@Injectable()
export class RolesGuard implements CanActivate {
    constructor(
        private reflector: Reflector,
        private authService: AuthService,
    ) { }

    canActivate(context: ExecutionContext): boolean {
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        const requiredPermissions = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (!requiredRoles && !requiredPermissions) {
            return true;
        }

        const request: AuthenticatedRequest = context.switchToHttp().getRequest();
        const user = request.user;

        if (!user) {
            throw new ForbiddenException('User information not found');
        }

        // Verificar roles
        if (requiredRoles && !this.authService.hasAnyRole(user, requiredRoles)) {
            throw new ForbiddenException(`Required roles: ${requiredRoles.join(', ')}`);
        }

        // Verificar permisos
        if (requiredPermissions) {
            const hasPermission = requiredPermissions.some(permission =>
                this.authService.hasPermission(user, permission)
            );

            if (!hasPermission) {
                throw new ForbiddenException(`Required permissions: ${requiredPermissions.join(', ')}`);
            }
        }

        return true;
    }
}

export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
export const Permissions = (...permissions: string[]) => SetMetadata(PERMISSIONS_KEY, permissions);