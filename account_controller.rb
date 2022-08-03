class V2::AccountController < ApplicationController
  before_action :app_key_check, only: [:sms_auth, :auth_code]
  before_action :authorize_application, only: [:firebase_token, :logout, :withdrawal_text, :withdrawal]

  # APIドキュメント ------------------------
  api :POST, '/account/sms_auth/phone', 'SMS/音声案内用の電話番号を送信'
  error :code => 401, :desc => "Unauthorized"
  error :code => 500, :desc => "Internal server error"
  param "W-ApplicationKey(header)", String, :desc => "アクセスキー(固定値)", :required => true
  param "phone_number", String, :desc => "電話番号 ex(09012345678)", :required => true
  param "authentication_method", %w[sms voice], :desc => "authentication_method", :required => true
  returns :code => 200, :desc => "成功" do
    property :message, String, :desc =>  "message"
  end
  returns :code => 400, :desc => "Bad request" do
    property :errors, Array, :desc => "バリデーションエラー"
  end
  # --------------------------------------
  def sms_auth
    country = get_country(request.remote_ip)
    case country
    when Settings.countries.jp, Settings.countries.us, Settings.countries.sg
    else
      # 国が取得できなかった場合（異常値）
      return render json: {errors: country}, status: :bad_request
    end

    case country
    when Settings.countries.jp
      I18n.locale = :ja
    when Settings.countries.us, Settings.countries.sg
      I18n.locale = :en
    end

    # 認証コード送信
    result = Auth0::Passwordless.get_code(params["phone_number"], country, params["authentication_method"])

    if result[:success]
      # 送信成功
      render json: {message: "success"}
    else
      if result[:validate]
        # 検証はOKだけど落ちた場合はなんらかのエラー
        logger.info result[:response]
        raise result[:response]
      else
        # 検証エラー
        return render json: {errors: result[:response].messages.map(&:text)}, status: :bad_request
      end
    end
  end

  # APIドキュメント ------------------------
  api :POST, '/account/sms_auth/auth_code', 'SMS認証コード送信'
  error :code => 401, :desc => "Unauthorized"
  error :code => 500, :desc => "Internal server error"
  param "W-ApplicationKey(header)", String, :desc => "アクセスキー(固定値)", :required => true
  param "phone_number", String, :desc => "電話番号 ex(09012345678)", :required => true
  param "auth_code", String, :desc => "４桁の数字", :required => true
  returns :code => 200, :desc => "成功" do
    property :app_user_id, Integer, :desc =>  "ユーザーID"
    property :access_token, String, :desc =>  "アクセストークン"
    property :refresh_token, String, :desc =>  "リフレッシュトークン"
    property :expiration_date, String, :desc =>  "アクセストークン有効期限"
    property :country, %w[JP US SG], :desc =>  "国"
  end
  returns :code => 400, :desc => "Bad request" do
    property :errors, Array, :desc => "バリデーションエラー"
  end
  # --------------------------------------
  def auth_code
    # response.set_header('HEADER-NAME', 'HEADER_VALUE')
    country = get_country(request.remote_ip)
    case country
    when Settings.countries.jp, Settings.countries.us, Settings.countries.sg
    else
      # 国が取得できなかった場合（異常値）
      return render json: {errors: country}, status: :bad_request
    end

    case country
    when Settings.countries.jp
      I18n.locale = :ja
    when Settings.countries.us, Settings.countries.sg
      I18n.locale = :en
    end

    # 認証コード送信
    expiration_date = Time.current.tomorrow.utc
    result = Auth0::Passwordless.auth_code(params["phone_number"], country, params["auth_code"])

    if result[:success]
      data = JSON.parse(result[:response].body)
      if result[:response].body =~ /error/
        return render json: {errors: [data["error_description"]]}, status: :bad_request
      else
        ActiveRecord::Base.transaction do
          case country
          when Settings.countries.jp
            # 既存ユーザーか確認する
            user = Jp::AppUser.where(phone_number: result[:phone_number])
            # 新規ユーザーであれば新しいレコードを作成
            user = user.size == 0 ? Jp::AppUser.create!(phone_number: result[:phone_number], last_login: Time.current, points: 0) : user.first
            # 新しいトークンの追加
            user.jp_app_user_auth_tokens.create!(expiration_date: expiration_date, access_token: data["access_token"])
          when Settings.countries.us
            # 既存ユーザーか確認する
            user = Us::AppUser.where(phone_number: result[:phone_number])
            # 新規ユーザーであれば新しいレコードを作成
            user = user.size == 0 ? Us::AppUser.create!(phone_number: result[:phone_number], last_login: Time.current, points: 0) : user.first
            # 新しいトークンの追加
            user.us_app_user_auth_tokens.create!(expiration_date: expiration_date, access_token: data["access_token"])
          when Settings.countries.sg
            # 既存ユーザーか確認する
            user = Sg::AppUser.where(phone_number: result[:phone_number])
            # 新規ユーザーであれば新しいレコードを作成
            user = user.size == 0 ? Sg::AppUser.create!(phone_number: result[:phone_number], last_login: Time.current, points: 0) : user.first
            # 新しいトークンの追加
            user.sg_app_user_auth_tokens.create!(expiration_date: expiration_date, access_token: data["access_token"])
          end

          # 送信成功
          render json: {
            app_user_id: user.id,
            access_token: data["access_token"],
            refresh_token: data["refresh_token"],
            expiration_date: expiration_date.to_s.gsub(/[^\d]/, ""),
            country: country
          }, status: :ok
        end
      end
    else
      if result[:validate]
        # 検証はOKだけど落ちた場合はなんらかのエラー
        logger.info result[:response]
        raise result[:response]
      else
        # 検証エラー
        return render json: {errors: result[:response].messages.map(&:text)}, status: :bad_request
      end
    end
  end

  # APIドキュメント ------------------------
  api :POST, '/account/refresh_token', 'アクセストークンをリフレッシュ'
  error :code => 400, :desc => "Bad request"
  error :code => 401, :desc => "Unauthorized"
  error :code => 500, :desc => "Internal server error"
  param "W-Authorization(header)", String, :desc => "アクセストークン", :required => true
  param "W-Country(header)", %w[JP US SG], :desc => "国", :required => true
  param "refresh_token", String, :desc => "リフレッシュトークン", :required => true
  returns :code => 200, :desc => "成功" do
    property :refresh_token, String, :desc =>  "リフレッシュトークン"
    property :access_token, String, :desc =>  "アクセストークン"
    property :expiration_date, String, :desc =>  "アクセストークン有効期限"
    property :country, %w[JP US SG], :desc =>  "国"
    property :icon, String, :desc =>  "プロフィール画像URL"
  end
  # --------------------------------------
  def refresh_token
    # AppUserAuthTokenテーブルを検索
    case request.headers["W-Country"]
    when Settings.countries.jp
      token = Jp::AppUserAuthToken.where(access_token: request.headers['W-Authorization'])
    when Settings.countries.us
      token = Us::AppUserAuthToken.where(access_token: request.headers['W-Authorization'])
    when Settings.countries.sg
      token = Sg::AppUserAuthToken.where(access_token: request.headers['W-Authorization'])
    end
    if token.nil? || token.size != 1
      # 見つからなければエラー
      return render json: { error: "unauthorized" }, status: :unauthorized
    end
    token = token.first

    # 新しいトークンを取得
    expiration_date = Time.current.tomorrow.utc
    result = Auth0::Passwordless.refresh_token(params["refresh_token"])

    if result[:success]
      if result[:response].body =~ /access_token/
        data = JSON.parse(result[:response].body)

        # レスポンスが正しいかチェック
        jwt = Auth0::JsonWebToken.verify(data["id_token"])

        # 国分岐
        case request.headers["W-Country"]
        when Settings.countries.jp
          app_user = token.jp_app_user
          profile = app_user.jp_app_user_setting_profile
        when Settings.countries.us
          app_user = token.us_app_user
          profile = app_user.us_app_user_setting_profile
        when Settings.countries.sg
          app_user = token.sg_app_user
          profile = app_user.sg_app_user_setting_profile
        end

        # 一応電話番号が合ってるか確認する
        if app_user.phone_number == jwt.first["phone_number"]
          #トークンの更新
          token.access_token = data["access_token"]
          token.expiration_date = expiration_date
          token.save

          # 送信成功
          render json: {
            access_token: data["access_token"],
            expiration_date: expiration_date.to_s.gsub(/[^\d]/, ""),
            country: request.headers["W-Country"],
            refresh_token: params["refresh_token"],
            icon: profile.nil? ? '' : profile.icon.url
          }, status: :ok
        else
          render json: { error: "bad_request" }, status: :bad_request
        end
      else
        render json: { error: "invalid refresh token." }, status: :unauthorized
      end
    else
      raise result[:response]
    end
  end

  # APIドキュメント ------------------------
  api :POST, '/account/firebase_token/register', 'アプリのFirebaseトークンを登録する'
  error :code => 400, :desc => "Bad request"
  error :code => 401, :desc => "Unauthorized"
  error :code => 500, :desc => "Internal server error"
  param "W-Authorization(header)", String, :desc => "アクセストークン", :required => true
  param "W-Country(header)", %w[JP US SG], :desc => "国", :required => true
  param "firebase_token", String, :desc => "firebaseトークン", :required => true
  param "period_push_enabled", String, :desc => "保証期限通知 許可フラグ", :required => true
  param "notices_push_enabled", String, :desc => "お知らせ通知 許可フラグ", :required => true
  returns :code => 200, :desc => "成功"
  # --------------------------------------
  def firebase_token
    if params["firebase_token"].blank?
      return render json: { error: "Bad request" }, status: :bad_request
    end
    
    @token.firebase_token = params["firebase_token"]
    @token.period_push_enabled = params["period_push_enabled"]
    @token.notices_push_enabled = params["notices_push_enabled"]
    @token.save!

    render json: :success, status: :ok
  end

  # APIドキュメント ------------------------
  api :POST, '/account/logout', 'ユーザのログアウト'
  error :code => 401, :desc => "Unauthorized"
  error :code => 500, :desc => "Internal server error"
  param "W-Authorization(header)", String, :desc => "アクセストークン", :required => true
  param "W-Country(header)", %w[JP US SG], :desc => "国", :required => true
  returns :code => 200, :desc => "成功"
  # --------------------------------------
  def logout
    @token.destroy!
    render json: :success, status: :ok
  end

  # APIドキュメント ------------------------
  api :GET, '/account/withdrawal_text', '退会の文言用を返します'
  error :code => 401, :desc => "Unauthorized"
  error :code => 500, :desc => "Internal server error"
  param "W-Authorization(header)", String, :desc => "アクセストークン", :required => true
  param "W-Language(header)", [:ja, :en], :desc => "言語", :required => true
  param "W-Country(header)", [:JP, :US, :SG], :desc => "国", :required => true
  returns :code => 200, :desc => "成功" do
    property :text, String, :desc => "プライバシーポリシーのテキストです・・・・・・・・・"
  end
  # --------------------------------------
  def withdrawal_text
    case request.headers["W-Country"]
    when Settings.countries.jp
      file_name = 'withdrawal_jp.json'
    when Settings.countries.us
      file_name = 'withdrawal_us.txt'
    when Settings.countries.sg
      file_name = 'withdrawal_sg.txt'
    end

    file = File.open("#{Rails.root}/public/withdrawal/#{file_name}","r")
    render json: { text: file.read }, status: :ok
  end

  # APIドキュメント ------------------------
  api :POST, '/account/withdrawal', 'ユーザの退会'
  error :code => 401, :desc => "Unauthorized"
  error :code => 500, :desc => "Internal server error"
  param "W-Authorization(header)", String, :desc => "アクセストークン", :required => true
  param "W-Country(header)", %w[JP US SG], :desc => "国", :required => true
  returns :code => 200, :desc => "成功"
  # --------------------------------------
  def withdrawal
    case request.headers["W-Country"]
    when Settings.countries.jp
      user = @token.jp_app_user
    when Settings.countries.us
      user = @token.us_app_user
    when Settings.countries.sg
      user = @token.sg_app_user
    end
    user.withdrawal

    render json: {}, status: :ok
  end

  private

  def get_country(ip)
    # IPから国を判定
    input = {ip_address: ip}

    geoip = Interactor::Geoip.new(**input).get_country
    if !geoip[:success]
      if geoip[:validate]
        case geoip[:response]
        when MaxMind::GeoIP2::AddressNotFoundError
          # IPが該当しない場合は無視してJP
          return Settings.countries.jp
        else
          # 検証はOKだけど落ちた場合はなんらかのエラー
          logger.info geoip[:response]
          raise geoip[:response]
        end
      else
        # 検証エラー
        return geoip[:response].messages.map(&:text)
      end
    end

    return geoip[:response]
  end
end
