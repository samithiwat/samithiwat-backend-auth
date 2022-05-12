import { faker } from '@faker-js/faker';
import { HttpStatus } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ServiceType } from 'src/common/enum/auth.enum';
import { CreateTokenDto } from '../dto/create-token.dto';
import { ResponseDto } from '../dto/response.dto';
import { UpdateTokenDto } from '../dto/update-token.dto';
import { Auth } from '../entities/auth.entity';
import { Token } from '../entities/token.entity';
import { TokenResponse } from '../interface/token.interface';
import { JwtService } from './jwt.service';
import { RefreshTokenService } from './refresh-token.service';
import { TokenService } from './token.service';

const MockTokenRepository = {
  save: jest.fn(),
  findOne: jest.fn(),
  softDelete: jest.fn(),
};

const MockJwtService = {
  generate: jest.fn(),
};

const MockRefreshTokenService = {
  generate: jest.fn(),
};

describe('TokenService', () => {
  let tokenService: TokenService;
  let mockTokenDto: CreateTokenDto;
  let mockToken: Token;

  beforeEach(async () => {
    const tokenModule: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.registerAsync({
          imports: [ConfigModule],
          useFactory: async (configService: ConfigService) => ({
            secret: configService.get<string>('jwt.secret'),
            signOptions: { expiresIn: configService.get<string>('jwt.tokenDuration') },
          }),
          inject: [ConfigService],
        }),
      ],
      providers: [
        TokenService,
        {
          provide: JwtService,
          useValue: MockJwtService,
        },
        {
          provide: RefreshTokenService,
          useValue: MockRefreshTokenService,
        },
        {
          provide: getRepositoryToken(Token),
          useValue: MockTokenRepository,
        },
      ],
    }).compile();

    mockTokenDto = new CreateTokenDto({
      serviceType: ServiceType.APP,
      accessToken: faker.lorem.text(),
      refreshToken: faker.lorem.text(),
      expiresDate: faker.date.soon(),
      auth: new Auth({ id: 1 }),
    });

    mockToken = new Token({
      id: 1,
      serviceType: ServiceType.APP,
      accessToken: faker.lorem.text(),
      refreshToken: faker.lorem.text(),
      expiresDate: faker.date.soon(),
    });

    tokenService = tokenModule.get<TokenService>(TokenService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(tokenService).toBeDefined();
  });

  describe('create', () => {
    it('should return auth when success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockToken,
      });
      MockTokenRepository.save.mockResolvedValue(mockToken);

      const res = await tokenService.create(mockTokenDto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.save).toBeCalledWith(mockTokenDto);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
    });

    it('should throw error if refresh token is duplicated', async () => {
      const want: ResponseDto = new ResponseDto({
        statusCode: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: ['Refresh token already exists'],
        data: null,
      });

      MockTokenRepository.save.mockImplementation(() => {
        throw new Error('Duplicated refresh token');
      });

      const res = await tokenService.create(mockTokenDto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(0);
    });

    it('should create new access token if dto does have provided', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockToken,
      });
      const newAccessToken = faker.lorem.word();

      (want.data as Token).accessToken = newAccessToken;

      MockJwtService.generate.mockResolvedValue(newAccessToken);
      MockTokenRepository.save.mockResolvedValue(mockToken);

      mockTokenDto.accessToken = undefined;

      const res = await tokenService.create(mockTokenDto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.save).toBeCalledWith(mockTokenDto);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
      expect(MockJwtService.generate).toBeCalledTimes(1);
    });

    it('should create new refresh token if dto does have provided', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockToken,
      });
      const newRefreshToken = faker.lorem.word();

      (want.data as Token).refreshToken = newRefreshToken;

      MockRefreshTokenService.generate.mockResolvedValue(newRefreshToken);
      MockTokenRepository.save.mockResolvedValue(mockToken);

      mockTokenDto.refreshToken = undefined;

      const res = await tokenService.create(mockTokenDto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.save).toBeCalledWith(mockTokenDto);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
      expect(MockRefreshTokenService.generate).toBeCalledTimes(1);
    });
  });

  describe('findOne', () => {
    it('should return the token that find with id if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockToken,
      });

      MockTokenRepository.findOne.mockResolvedValue(mockToken);

      const res = await tokenService.findOne(1);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.findOne).toBeCalledWith(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(1);
    });

    it('should throw error if not found token', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.NOT_FOUND,
        errors: ['Not found token'],
        data: null,
      });

      MockTokenRepository.findOne.mockResolvedValue(undefined);

      const res = await tokenService.findOne(1);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.findOne).toBeCalledWith(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(1);
    });
  });

  describe('update', () => {
    it('should return token if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockToken,
      });

      MockTokenRepository.save.mockResolvedValue(mockToken);
      MockTokenRepository.findOne.mockResolvedValue(want);

      const dto = new UpdateTokenDto();
      const res = await tokenService.update(1, dto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.findOne).toBeCalledWith(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(1);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
    });

    it('should throw error if not found token', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.NOT_FOUND,
        errors: ['Not found token'],
        data: null,
      }) as TokenResponse;

      jest.spyOn(tokenService, 'findOne').mockResolvedValue(want);

      const dto = new UpdateTokenDto();
      const res = await tokenService.update(1, dto);

      expect(res).toStrictEqual(want);
      expect(tokenService.findOne).toBeCalledWith(1);
      expect(tokenService.findOne).toBeCalledTimes(1);
      expect(MockTokenRepository.save).toBeCalledTimes(0);
    });

    it('should throw error if refresh token is duplicated', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: ['Refresh token already exists'],
        data: null,
      });

      MockTokenRepository.save.mockImplementation(() => {
        throw new Error('Duplicated refresh token');
      });

      const dto = new UpdateTokenDto();
      const res = await tokenService.update(1, dto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.findOne).toBeCalledWith(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(1);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
    });
  });
});
