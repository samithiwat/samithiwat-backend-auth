import { HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import * as crypto from 'crypto-js';
import * as moment from 'moment';
import { ServiceType } from 'src/common/enum/auth.enum';
import { Repository } from 'typeorm';
import { CreateTokenDto } from '../dto/create-token.dto';
import { ResponseDto } from '../dto/response.dto';
import { UpdateTokenDto } from '../dto/update-token.dto';
import { Token } from '../entities/token.entity';
import { TokenResponse } from '../interface/token.interface';
import { JwtService } from './jwt.service';
import { RefreshTokenService } from './refresh-token.service';

@Injectable()
export class TokenService {
  constructor(
    @InjectRepository(Token) private readonly tokenRepository: Repository<Token>,
    private readonly jwtService: JwtService,
    private readonly refreshTokenService: RefreshTokenService,
    private readonly configService: ConfigService,
  ) {}

  async create(createTokenDto: CreateTokenDto): Promise<TokenResponse> {
    // Token is already encoded
    const res = new ResponseDto({
      statusCode: HttpStatus.CREATED,
      errors: null,
      data: null,
    }) as TokenResponse;

    createTokenDto.accessToken = createTokenDto.accessToken
      ? createTokenDto.accessToken
      : await this.jwtService.generate(createTokenDto.auth);

    createTokenDto.refreshToken = createTokenDto.refreshToken
      ? createTokenDto.refreshToken
      : await this.refreshTokenService.generate();

    createTokenDto.expiresDate = createTokenDto.expiresDate
      ? createTokenDto.expiresDate
      : moment()
          .add(parseInt(this.configService.get<string>('jwt.tokenDuration')), 's')
          .toDate();

    try {
      const token = await this.tokenRepository.save(createTokenDto);

      if (token.serviceType === ServiceType.APP) {
        token.refreshToken = await this.encode(token.refreshToken);
      }

      res.data = token;
    } catch (err) {
      res.statusCode = HttpStatus.UNPROCESSABLE_ENTITY;
      res.errors = ['Refresh token already exists'];
    }
    return res;
  }

  async findOne(id: number): Promise<TokenResponse> {
    const token = await this.tokenRepository.findOne(id);

    return new ResponseDto({
      statusCode: token ? HttpStatus.OK : HttpStatus.NOT_FOUND,
      errors: token ? null : ['Not found token'],
      data: token ? token : null,
    }) as TokenResponse;
  }

  async update(id: number, updateTokenDto: UpdateTokenDto): Promise<TokenResponse> {
    const searchResult = await this.findOne(id);

    if (searchResult.statusCode !== HttpStatus.OK) {
      return searchResult;
    }

    try {
      const token = await this.tokenRepository.save({ id, ...updateTokenDto });

      if (token.serviceType === ServiceType.APP) {
        token.refreshToken = await this.encode(token.refreshToken);
      }

      searchResult.data = token;
    } catch (err) {
      searchResult.statusCode = HttpStatus.UNPROCESSABLE_ENTITY;
      searchResult.errors = ['Refresh token already exists'];
      searchResult.data = null;
    }
    return searchResult;
  }

  async remove(id: number): Promise<TokenResponse> {
    const res = await this.findOne(id);

    if (res.statusCode !== HttpStatus.OK) {
      return res;
    }

    await this.tokenRepository.softDelete(id);
    return res;
  }

  async encode(token: string): Promise<string> {
    return crypto.AES.encrypt(token, this.configService.get<string>('jwt.secret')).toString();
  }

  async decode(token: string): Promise<string> {
    return crypto.AES.decrypt(token, this.configService.get<string>('jwt.secret')).toString(
      crypto.enc.Utf8,
    );
  }
}
