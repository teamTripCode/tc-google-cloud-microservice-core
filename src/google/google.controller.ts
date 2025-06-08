import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { GoogleService } from './google.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';

@ApiTags('Google Check')
@Controller()
@UseGuards(JwtAuthGuard)
export class GoogleController {
    constructor(private readonly googleService: GoogleService) { }

    @Get()
    @ApiOperation({
        summary: 'Health check',
        description: 'Simple health check endpoint to verify the service is running',
    })
    @ApiResponse({
        status: 200,
        description: 'Service is healthy',
        schema: {
            type: 'string',
            example: 'Is Active Session',
        },
    })
    getHello(): string {
        return this.googleService.testMessage();
    }
}
