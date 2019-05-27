Pod::Spec.new do |s|
  s.name         = "GoldenKey"
  s.version      = "1.0.0"
  s.summary      = "CommonCrypto and Security wrapper for iOS"
  
  s.description  = <<-DESC
		   Swift wrapper around CommonCrypto and Security frameworks.
                   DESC

  s.homepage     = "https://github.com/RedMadRobot/golden-key"
  s.license      = { :type => "MIT"}
  s.author       = { "Alexander Ignatiev" => "ai@redmadrobot.com", "Anton Glezman" => "a.glezman@redmadrobot.com" }
  s.source       = { :git => "https://github.com/RedMadRobot/golden-key.git", :tag => "#{s.version}" }

  s.ios.deployment_target = "10.0"
  s.tvos.deployment_target = "10.0"
  s.osx.deployment_target = "10.10"
  s.watchos.deployment_target = "4.0"

  s.swift_version = "5.0"
  s.source_files  = "GoldenKey/**/*.swift"
end
