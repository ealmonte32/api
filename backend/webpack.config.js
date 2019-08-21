const Webpack = require('webpack');
const Path = require('path');
const TerserPlugin = require('terser-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const OptimizeCSSAssetsPlugin = require('optimize-css-assets-webpack-plugin');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const HardSourceWebpackPlugin = require('hard-source-webpack-plugin');
const FileManagerPlugin = require('filemanager-webpack-plugin');
const BundleTracker = require('webpack-bundle-tracker');

module.exports = {
  entry: {
    app: ['./backend/static/js/app','./backend/static/scss/app'],
  },
  mode: process.env.NODE_ENV === 'production' ? 'production' : 'development',
  devtool: process.env.NODE_ENV === 'production' ? 'source-map' : 'inline-source-map',
  output: {path: Path.resolve('./backend/static/bundles/'),filename:"[name]-[hash].js"},
  performance: { hints: false },
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        cache: true,
        sourceMap: false,
          terserOptions: {
            output: {
              comments: false
            }
          }
      }),
      new OptimizeCSSAssetsPlugin({})
    ]
  },
  plugins: [
    new MiniCssExtractPlugin({filename: '[name]-[hash].css',chunkFilename: '[id].css'}),
    new Webpack.ProvidePlugin({$: 'jquery',jQuery: 'jquery','window.$': 'jquery','window.jQuery': 'jquery',Popper: ['popper.js', 'default']}),
    new HardSourceWebpackPlugin(),
    new BundleTracker({filename: './webpack-stats.json'})
  ],
  module: {
    rules: [
      {test: /\.js$/,exclude: /(node_modules)/,loader: ['babel-loader']},
      {test: /\.scss$/,use: [MiniCssExtractPlugin.loader,'css-loader','postcss-loader','sass-loader']},
      {test   : /\.(ttf|eot|svg|woff(2)?)(\?[a-z0-9=&.]+)?$/,loader : 'url-loader',options: {limit: 100000}},
      {test   : /\.(png|jpg|jpeg|gif?)(\?[a-z0-9=&.]+)?$/,loader : 'url-loader',options: {limit: 100000}},
      {test: require.resolve('jquery'),use: [{loader: 'expose-loader',options: 'jQuery'},{loader: 'expose-loader',options: '$'}]}
    ]
  },
  resolve: {
    extensions: ['.js', '.scss'],
    modules: ['node_modules'],
    alias: {request$: 'xhr'}
  }
}