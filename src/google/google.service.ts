import { Injectable } from '@nestjs/common';

@Injectable()
export class GoogleService {
  public testMessage(): string {
    return 'Is Active Session';
  }
}