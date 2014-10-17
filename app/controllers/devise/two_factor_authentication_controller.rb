class Devise::TwoFactorAuthenticationController < DeviseController
  prepend_before_filter :authenticate_scope!
  before_filter :prepare_and_validate, :handle_two_factor_authentication

  def show
  end

  def update
    render :show and return if params[:code].nil? && request.format.html?

    if resource.authenticate_otp(params[:code])
      warden.session(resource_name)[TwoFactorAuthentication::NEED_AUTHENTICATION] = false
      sign_in resource_name, resource, :bypass => true
      set_flash_message :notice, :success
      respond_to do |format|
        format.html { redirect_to stored_location_for(resource_name) || :root }
        format.json { render json: resource }
      end
      resource.update_attribute(:second_factor_attempts_count, 0)
    else
      resource.second_factor_attempts_count += 1
      resource.save
      flash.now[:error] = find_message(:attempt_failed)
      if resource.max_login_attempts?
        sign_out(resource)
        resource.errors.add(:base, 'Access completely denied as you have reached your attempts limit.')
        respond_to do |format|
          format.html { render :max_login_attempts_reached }
          format.json { render json: { errors: resource.errors }, status: :forbidden }
        end
      else
        resource.errors.add(:base, 'The two-factor authentication code entered was incorrect.')
        respond_to do |format|
          format.html { render :show }
          format.json { render json: { errors: resource.errors }, status: :forbidden }
        end
      end
    end
  end

  private

    def authenticate_scope!
      self.resource = send("current_#{resource_name}")
    end

    def prepare_and_validate
      redirect_to :root and return if resource.nil? && request.format.html?
      @limit = resource.max_login_attempts
      if resource.max_login_attempts?
        sign_out(resource)
        resource.errors.add(:base, 'Access completely denied as you have reached your attempts limit.')
        respond_to do |format|
          format.html { render :max_login_attempts_reached and return }
          format.json { render json: { errors: resource.errors }, status: :forbidden and return }
        end
      end
    end
end
